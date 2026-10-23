using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Intelligence.Analyst;

/// <summary>
/// Any model behind an OpenAI-compatible chat completions endpoint: OpenAI (ChatGPT), OpenRouter (for example
/// openai/gpt-oss-20b) or a model running on this computer through Ollama or LM Studio. These models get the
/// evidence pack in one call and no tools, because smaller and local models are unreliable at multi-step tool use.
/// Output that is not valid JSON in the expected shape is treated as no assessment.
/// </summary>
public class OpenAiCompatibleModel : IAnalystModel
{
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromMinutes(5) };

    private readonly string endpoint;
    private readonly string? apiKey;
    private readonly string model;
    private readonly bool isOpenRouter;

    public OpenAiCompatibleModel(string endpoint, string? apiKey, string model)
    {
        this.endpoint = endpoint.TrimEnd('/');
        this.apiKey = apiKey;
        this.model = model;
        isOpenRouter = endpoint.Contains("openrouter.ai", StringComparison.OrdinalIgnoreCase);
    }

    public string ModelName => model;

    public bool SupportsDeepInvestigation => false;

    public async Task<AnalystRunResult> Assess(AnalystCase analystCase, string evidencePack, string hostContext, string? baselineProfile, CancellationToken cancellationToken)
    {
        var systemPrompt = AnalystPrompt.Instructions
            + "\n\nAnswer with a single JSON object and nothing else, with exactly these fields: verdict (\"benign\", \"needs_attention\" or \"malicious\"), "
            + "confidence (0 to 1), title, explanation, recommended_action, remember_days (1 to 30), envelope_bytes_out_per_hour (integer), proposes_suppression (true or false)."
            + "\n\nAbout this computer:\n" + hostContext
            + "\n\nBaseline profile:\n" + (baselineProfile ?? "Not written yet.");
        var userPrompt = "Assess this case from the evidence gathered below.\n\n" + AnalystTools.Wrap(analystCase.Describe()) + "\n\n" + evidencePack;

        var (content, tokens) = await Complete(systemPrompt, [(true, userPrompt)], useJsonSchema: true, cancellationToken);
        var conclusion = AnalystPrompt.ParseConclusion(ExtractJson(content));
        return new AnalystRunResult(conclusion, conclusion == null ? "The model did not return a usable assessment." : null,
            tokens.Input, tokens.Output, 0, 0, model);
    }

    public Task<AnalystRunResult> Investigate(AnalystCase analystCase, string hostContext, string? baselineProfile, AnalystTools analystTools, CancellationToken cancellationToken)
    {
        return Task.FromResult(new AnalystRunResult(null, "Deep investigation is only available with Claude.", 0, 0, 0, 0, model));
    }

    public async Task<(string? Profile, long Tokens)> WriteBaselineProfile(string hostContext, string observedActivity, CancellationToken cancellationToken)
    {
        var userPrompt = "Write a baseline profile of 150 to 300 words describing what normal network activity looks like on this computer: "
            + "what kind of machine it is, which programs use the network and where they go, overlay networks and remote-access tools, "
            + "and anything that deserves a second look. Reply with the profile text only.\n\nHost context:\n" + hostContext + "\n\n" + AnalystTools.Wrap(observedActivity);
        var (content, tokens) = await Complete(AnalystPrompt.Instructions, [(true, userPrompt)], useJsonSchema: false, cancellationToken);
        return (string.IsNullOrWhiteSpace(content) ? null : content.Trim(), tokens.Input + tokens.Output);
    }

    public async Task<(string Reply, long Tokens)> Reply(string systemPrompt, IReadOnlyList<(bool FromUser, string Text)> conversation, CancellationToken cancellationToken)
    {
        var (content, tokens) = await Complete(systemPrompt, conversation, useJsonSchema: false, cancellationToken);
        return (content.Trim(), tokens.Input + tokens.Output);
    }

    /// <summary>
    /// Sends a chat completion. Structured output is requested with a JSON schema first; providers that reject it
    /// are retried with plain JSON mode.
    /// </summary>
    private async Task<(string Content, (long Input, long Output) Tokens)> Complete(
        string systemPrompt,
        IReadOnlyList<(bool FromUser, string Text)> conversation,
        bool useJsonSchema,
        CancellationToken cancellationToken)
    {
        var messages = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = systemPrompt } };
        foreach (var (fromUser, text) in conversation)
            messages.Add(new JsonObject { ["role"] = fromUser ? "user" : "assistant", ["content"] = text });

        var request = new JsonObject { ["model"] = model, ["messages"] = messages };
        if (useJsonSchema)
            request["response_format"] = JsonNode.Parse(JsonSerializer.Serialize(new
            {
                type = "json_schema",
                json_schema = new { name = "assessment", strict = true, schema = AnalystPrompt.ConclusionSchema }
            }));

        var response = await Send(request, cancellationToken);
        if (useJsonSchema && response.StatusCode == System.Net.HttpStatusCode.BadRequest)
        {
            response.Dispose();
            request["response_format"] = new JsonObject { ["type"] = "json_object" };
            response = await Send(request, cancellationToken);
        }

        using (response)
        {
            var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"{endpoint} answered {(int)response.StatusCode}: {AnalystPrompt.Truncate(responseText, 300)}");

            var responseNode = JsonNode.Parse(responseText);
            var content = responseNode?["choices"]?[0]?["message"]?["content"]?.GetValue<string>() ?? string.Empty;
            var inputTokens = responseNode?["usage"]?["prompt_tokens"]?.GetValue<long>() ?? 0;
            var outputTokens = responseNode?["usage"]?["completion_tokens"]?.GetValue<long>() ?? 0;
            return (content, (inputTokens, outputTokens));
        }
    }

    private async Task<HttpResponseMessage> Send(JsonObject request, CancellationToken cancellationToken)
    {
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint + "/chat/completions")
        {
            Content = JsonContent.Create(request)
        };

        if (!string.IsNullOrEmpty(apiKey))
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        if (isOpenRouter)
        {
            httpRequest.Headers.Add("HTTP-Referer", "https://github.com/scoutwall");
            httpRequest.Headers.Add("X-Title", "ScoutWall");
        }

        return await HttpClient.SendAsync(httpRequest, cancellationToken);
    }

    /// <summary>
    /// Some models wrap JSON in a code fence or add a sentence around it; take the outermost object.
    /// </summary>
    private static string ExtractJson(string content)
    {
        var start = content.IndexOf('{');
        var end = content.LastIndexOf('}');
        return start >= 0 && end > start ? content[start..(end + 1)] : content;
    }
}

/// <summary>
/// Creates the model the settings ask for, or null when the analyst is off or not configured.
/// </summary>
public static class AnalystModelFactory
{
    public static IAnalystModel? Create(AnalystSettings analystSettings)
    {
        if (!analystSettings.IsReady)
            return null;

        return analystSettings.Provider switch
        {
            AnalystProvider.Claude => new ClaudeAnalystModel(analystSettings),
            AnalystProvider.OpenAi => new OpenAiCompatibleModel(AnalystSettings.OpenAiEndpoint, SecretProtector.Unprotect(analystSettings.OpenAiApiKey), analystSettings.OpenAiModel),
            AnalystProvider.OpenRouter => new OpenAiCompatibleModel(AnalystSettings.OpenRouterEndpoint, SecretProtector.Unprotect(analystSettings.OpenRouterApiKey), analystSettings.OpenRouterModel),
            AnalystProvider.LocalModel => new OpenAiCompatibleModel(analystSettings.LocalEndpoint, null, analystSettings.LocalModel),
            _ => null
        };
    }
}

/// <summary>
/// Gathers the facts about a case up front with the same lookups the deep investigation uses.
/// </summary>
public static class EvidencePack
{
    public static async Task<string> Gather(AnalystTools analystTools, AnalystCase analystCase)
    {
        var sections = new List<string>();

        if (analystCase.RemoteIp != null)
            sections.Add("Destination:\n" + await analystTools.Execute("get_address_profile", Input(("ip", analystCase.RemoteIp))));

        if (analystCase.ProcessPath != null)
        {
            sections.Add("Program:\n" + await analystTools.Execute("get_program_profile", Input(("program_path", analystCase.ProcessPath))));
            sections.Add("Hourly history of this program with this destination (48 hours):\n" + await analystTools.Execute("get_traffic_history",
                Input(("program_path", analystCase.ProcessPath), ("ip", analystCase.RemoteIp ?? string.Empty), ("hours", 48))));
        }

        sections.Add("Related alerts:\n" + await analystTools.Execute("get_related_alerts",
            Input(("program_path", analystCase.ProcessPath ?? string.Empty), ("ip", analystCase.RemoteIp ?? string.Empty))));
        sections.Add("Earlier conclusions:\n" + await analystTools.Execute("get_prior_assessments",
            Input(("program_path", analystCase.ProcessPath ?? string.Empty), ("destination", analystCase.Destination ?? analystCase.RemoteIp ?? string.Empty))));

        return string.Join("\n\n", sections);
    }

    private static Dictionary<string, JsonElement> Input(params (string Name, object Value)[] values)
    {
        return values.ToDictionary(value => value.Name, value => JsonSerializer.SerializeToElement(value.Value));
    }
}
