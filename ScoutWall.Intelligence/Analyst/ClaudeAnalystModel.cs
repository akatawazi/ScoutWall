using System.Text.Json;
using Anthropic;
using Anthropic.Models.Beta;
using Anthropic.Models.Beta.Messages;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Intelligence.Analyst;

/// <summary>
/// The analyst: Claude investigates a case with read-only lookups and decides whether the person who owns
/// this computer needs to know about it. The loop is append-only so thinking is preserved between steps.
/// </summary>
public class ClaudeAnalystModel : IAnalystModel
{
    private const int MaximumSteps = 10;
    private const int MaximumOutputTokens = 16000;

    private readonly AnalystSettings analystSettings;
    private readonly AnthropicClient client;

    public ClaudeAnalystModel(AnalystSettings analystSettings)
    {
        this.analystSettings = analystSettings;
        client = new AnthropicClient
        {
            ApiKey = SecretProtector.Unprotect(analystSettings.ApiKey),
            Timeout = TimeSpan.FromMinutes(5)
        };
    }

    public string ModelName => analystSettings.Model;

    public bool SupportsDeepInvestigation => true;

    /// <summary>
    /// One call with every relevant fact gathered up front. Cheaper and easier to audit than a tool loop, and
    /// enough for most cases; the worker escalates to <see cref="Investigate"/> when this is unsure.
    /// </summary>
    public async Task<AnalystRunResult> Assess(AnalystCase analystCase, string evidencePack, string hostContext, string? baselineProfile, CancellationToken cancellationToken)
    {
        var messages = new List<BetaMessageParam>
        {
            new BetaUserMessageParam
            {
                Content = "Assess this case from the evidence gathered below and give your assessment.\n\n"
                    + AnalystTools.Wrap(analystCase.Describe()) + "\n\n" + evidencePack
            }
        };

        var response = await client.Beta.Messages.Create(BuildRequest(messages, hostContext, baselineProfile, includeTools: false), cancellationToken);
        var inputTokens = response.Usage.InputTokens + (response.Usage.CacheCreationInputTokens ?? 0) + (response.Usage.CacheReadInputTokens ?? 0);
        var cacheReadTokens = response.Usage.CacheReadInputTokens ?? 0;
        var stopReason = response.StopReason?.ToString() ?? string.Empty;
        if (stopReason.Contains("refusal", StringComparison.OrdinalIgnoreCase))
            return new AnalystRunResult(null, "The model declined to assess this case.", inputTokens, response.Usage.OutputTokens, cacheReadTokens, 0, ModelName);

        var (_, _, finalText) = ReadResponse(response);
        var conclusion = AnalystPrompt.ParseConclusion(finalText);
        return new AnalystRunResult(conclusion, conclusion == null ? "The model did not return a usable assessment." : null,
            inputTokens, response.Usage.OutputTokens, cacheReadTokens, 0, ModelName);
    }

    public async Task<(string Reply, long Tokens)> Reply(string systemPrompt, IReadOnlyList<(bool FromUser, string Text)> conversation, CancellationToken cancellationToken)
    {
        var messages = conversation
            .Select(turn => turn.FromUser
                ? (BetaMessageParam)new BetaUserMessageParam { Content = turn.Text }
                : new BetaAssistantMessageParam { Content = turn.Text })
            .ToList();

        var response = await client.Beta.Messages.Create(new MessageCreateParams
        {
            Model = analystSettings.Model,
            MaxTokens = MaximumOutputTokens,
            Thinking = new BetaThinkingConfigAdaptive(),
            OutputConfig = new BetaOutputConfig { Effort = "low" },
            Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
            Fallbacks = new Default(),
            System = new List<BetaTextBlockParam> { new() { Text = systemPrompt, CacheControl = new BetaCacheControlEphemeral() } },
            Messages = messages
        }, cancellationToken);

        var (_, _, replyText) = ReadResponse(response);
        return (replyText.Trim(), response.Usage.InputTokens + response.Usage.OutputTokens);
    }

    /// <summary>
    /// A chat turn in which Claude may call the given tools. Returns the final reply text, total tokens and the
    /// names of the tools it called. The loop is append-only within the turn.
    /// </summary>
    public async Task<(string Reply, long Tokens, List<string> ToolsCalled)> Converse(
        string systemPrompt,
        IReadOnlyList<(bool FromUser, string Text)> conversation,
        IReadOnlyList<AnalystToolDefinition> toolDefinitions,
        Func<string, IReadOnlyDictionary<string, JsonElement>, Task<string>> executeTool,
        CancellationToken cancellationToken)
    {
        var messages = conversation
            .Select(turn => turn.FromUser
                ? (BetaMessageParam)new BetaUserMessageParam { Content = turn.Text }
                : new BetaAssistantMessageParam { Content = turn.Text })
            .ToList();

        var tools = toolDefinitions.Select(definition => (BetaToolUnion)new BetaTool
        {
            Name = definition.Name,
            Description = definition.Description,
            InputSchema = new()
            {
                Properties = definition.Properties.ToDictionary(entry => entry.Key, entry => JsonSerializer.SerializeToElement(entry.Value)),
                Required = definition.Required
            }
        }).ToList();

        long tokens = 0;
        var toolsCalled = new List<string>();
        var replyText = string.Empty;

        for (var step = 0; step < MaximumSteps; step++)
        {
            var response = await client.Beta.Messages.Create(new MessageCreateParams
            {
                Model = analystSettings.Model,
                MaxTokens = MaximumOutputTokens,
                Thinking = new BetaThinkingConfigAdaptive(),
                OutputConfig = new BetaOutputConfig { Effort = "low" },
                Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
                Fallbacks = new Default(),
                System = new List<BetaTextBlockParam> { new() { Text = systemPrompt, CacheControl = new BetaCacheControlEphemeral() } },
                Tools = tools,
                Messages = messages
            }, cancellationToken);
            tokens += response.Usage.InputTokens + response.Usage.OutputTokens;

            var (assistantContent, toolUses, finalText) = ReadResponse(response);
            messages.Add(new BetaAssistantMessageParam { Content = assistantContent });
            replyText = finalText;

            if (toolUses.Count == 0)
                break;

            var toolResults = new List<BetaContentBlockParam>();
            foreach (var toolUse in toolUses)
            {
                toolsCalled.Add(toolUse.Name);
                toolResults.Add(new BetaToolResultBlockParam { ToolUseID = toolUse.ID, Content = await executeTool(toolUse.Name, toolUse.Input) });
            }

            messages.Add(new BetaUserMessageParam { Content = toolResults });
        }

        return (replyText.Trim(), tokens, toolsCalled);
    }

    public async Task<AnalystRunResult> Investigate(AnalystCase analystCase, string hostContext, string? baselineProfile, AnalystTools analystTools, CancellationToken cancellationToken)
    {
        var messages = new List<BetaMessageParam>
        {
            new BetaUserMessageParam
            {
                Content = "Investigate this case with the lookups and give your assessment.\n\n" + AnalystTools.Wrap(analystCase.Describe())
            }
        };

        long inputTokens = 0, outputTokens = 0, cacheReadTokens = 0;
        var toolCalls = 0;

        for (var step = 0; step < MaximumSteps; step++)
        {
            var response = await client.Beta.Messages.Create(BuildRequest(messages, hostContext, baselineProfile, includeTools: true), cancellationToken);
            inputTokens += response.Usage.InputTokens + (response.Usage.CacheCreationInputTokens ?? 0) + (response.Usage.CacheReadInputTokens ?? 0);
            outputTokens += response.Usage.OutputTokens;
            cacheReadTokens += response.Usage.CacheReadInputTokens ?? 0;

            var stopReason = response.StopReason?.ToString() ?? string.Empty;
            if (stopReason.Contains("refusal", StringComparison.OrdinalIgnoreCase))
                return new AnalystRunResult(null, "The model declined to assess this case.", inputTokens, outputTokens, cacheReadTokens, toolCalls, analystSettings.Model);

            var (assistantContent, toolUses, finalText) = ReadResponse(response);
            messages.Add(new BetaAssistantMessageParam { Content = assistantContent });

            if (toolUses.Count > 0)
            {
                var toolResults = new List<BetaContentBlockParam>();
                foreach (var toolUse in toolUses)
                {
                    toolCalls++;
                    var result = await analystTools.Execute(toolUse.Name, toolUse.Input);
                    toolResults.Add(new BetaToolResultBlockParam { ToolUseID = toolUse.ID, Content = result });
                }

                messages.Add(new BetaUserMessageParam { Content = toolResults });
                continue;
            }

            if (stopReason.Contains("pause_turn", StringComparison.OrdinalIgnoreCase))
                continue;

            var conclusion = AnalystPrompt.ParseConclusion(finalText);
            return conclusion == null
                ? new AnalystRunResult(null, $"The model did not return a usable assessment (stop reason {stopReason}).", inputTokens, outputTokens, cacheReadTokens, toolCalls, analystSettings.Model)
                : new AnalystRunResult(conclusion, null, inputTokens, outputTokens, cacheReadTokens, toolCalls, analystSettings.Model);
        }

        return new AnalystRunResult(null, "The investigation did not finish within the step limit.", inputTokens, outputTokens, cacheReadTokens, toolCalls, analystSettings.Model);
    }

    /// <summary>
    /// Writes a short description of what is normal on this computer, used as context for later cases.
    /// </summary>
    public async Task<(string? Profile, long Tokens)> WriteBaselineProfile(string hostContext, string observedActivity, CancellationToken cancellationToken)
    {
        var response = await client.Beta.Messages.Create(new MessageCreateParams
        {
            Model = analystSettings.Model,
            MaxTokens = MaximumOutputTokens,
            Thinking = new BetaThinkingConfigAdaptive(),
            OutputConfig = new BetaOutputConfig { Effort = analystSettings.Effort },
            Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
            Fallbacks = new Default(),
            System = new List<BetaTextBlockParam> { new() { Text = AnalystPrompt.Instructions } },
            Messages =
            [
                new BetaUserMessageParam
                {
                    Content = "ScoutWall has finished learning what normal network activity looks like on this computer. "
                        + "Write a baseline profile of 150 to 300 words that a future analyst can use to judge new activity: "
                        + "what kind of machine this appears to be, which programs and services normally use the network and where they go, "
                        + "overlay networks and remote-access tools present, and anything in the baseline itself that deserves a second look. "
                        + "Reply with the profile text only.\n\n"
                        + "Host context:\n" + hostContext + "\n\n"
                        + AnalystTools.Wrap(observedActivity)
                }
            ]
        }, cancellationToken);

        var profileText = string.Join("\n", response.Content.Select(block => block.TryPickText(out var text) ? text.Text : null).OfType<string>()).Trim();
        var tokens = response.Usage.InputTokens + response.Usage.OutputTokens;
        return (string.IsNullOrEmpty(profileText) ? null : profileText, tokens);
    }

    private MessageCreateParams BuildRequest(List<BetaMessageParam> messages, string hostContext, string? baselineProfile, bool includeTools)
    {
        var contextText = "About this computer:\n" + hostContext
            + "\n\nBaseline profile (what normal looks like here):\n" + (baselineProfile ?? "Not written yet; ScoutWall is still learning this computer.");

        var tools = AnalystTools.Definitions
            .Select(definition => (BetaToolUnion)new BetaTool
            {
                Name = definition.Name,
                Description = definition.Description,
                InputSchema = new()
                {
                    Properties = definition.Properties.ToDictionary(entry => entry.Key, entry => JsonSerializer.SerializeToElement(entry.Value)),
                    Required = definition.Required
                }
            })
            .ToList();

        if (!includeTools)
            tools.Clear();
        else if (analystSettings.WebSearchEnabled)
            tools.Add(new BetaWebSearchTool20260209 { MaxUses = 3, AllowedDomains = analystSettings.WebSearchDomains });

        return new MessageCreateParams
        {
            Model = analystSettings.Model,
            MaxTokens = MaximumOutputTokens,
            Thinking = new BetaThinkingConfigAdaptive(),
            OutputConfig = new BetaOutputConfig
            {
                Effort = analystSettings.Effort,
                Format = new BetaJsonOutputFormat { Schema = AnalystPrompt.ConclusionSchema }
            },
            Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
            Fallbacks = new Default(),
            System = new List<BetaTextBlockParam>
            {
                new() { Text = AnalystPrompt.Instructions },
                new() { Text = contextText, CacheControl = new BetaCacheControlEphemeral() }
            },
            Tools = tools.Count > 0 ? tools : null,
            Messages = messages
        };
    }

    private static (List<BetaContentBlockParam> AssistantContent, List<BetaToolUseBlock> ToolUses, string FinalText) ReadResponse(BetaMessage response)
    {
        var assistantContent = new List<BetaContentBlockParam>();
        var toolUses = new List<BetaToolUseBlock>();
        var finalText = string.Empty;

        foreach (var block in response.Content)
        {
            if (block.TryPickText(out var text))
            {
                assistantContent.Add(new BetaTextBlockParam { Text = text.Text });
                finalText += text.Text;
            }
            else if (block.TryPickThinking(out var thinking))
            {
                assistantContent.Add(new BetaThinkingBlockParam { Thinking = thinking.Thinking, Signature = thinking.Signature });
            }
            else if (block.TryPickRedactedThinking(out var redactedThinking))
            {
                assistantContent.Add(new BetaRedactedThinkingBlockParam { Data = redactedThinking.Data });
            }
            else if (block.TryPickToolUse(out var toolUse))
            {
                assistantContent.Add(new BetaToolUseBlockParam { ID = toolUse.ID, Name = toolUse.Name, Input = toolUse.Input });
                toolUses.Add(toolUse);
            }
            else if (block.TryPickServerToolUse(out var serverToolUse))
            {
                assistantContent.Add(new BetaServerToolUseBlockParam { ID = serverToolUse.ID, Name = serverToolUse.Name.Raw(), Input = serverToolUse.Input });
            }
            else if (block.TryPickWebSearchToolResult(out var webSearchResult))
            {
                assistantContent.Add(new BetaWebSearchToolResultBlockParam { ToolUseID = webSearchResult.ToolUseID, Content = ToParam(webSearchResult.Content) });
            }
        }

        return (assistantContent, toolUses, finalText);
    }

    /// <summary>
    /// Web search results must be echoed back unchanged (including their encrypted content) on the next turn.
    /// </summary>
    private static BetaWebSearchToolResultBlockParamContent ToParam(BetaWebSearchToolResultBlockContent content)
    {
        if (content.TryPickError(out var error))
            return new BetaWebSearchToolRequestError { ErrorCode = error.ErrorCode.Raw() };

        content.TryPickBetaWebSearchResultBlocks(out var resultBlocks);
        return (resultBlocks ?? [])
            .Select(resultBlock => new BetaWebSearchResultBlockParam
            {
                EncryptedContent = resultBlock.EncryptedContent,
                Title = resultBlock.Title,
                Url = resultBlock.Url,
                PageAge = resultBlock.PageAge
            })
            .ToList();
    }

}
