namespace ScoutWall.Data.Models;

public enum ProtectionChoice
{
    JustTellMe = 1,
    BlockAutomatically = 2,
    SlowItDown = 3,
    BlockWhileAway = 4
}

/// <summary>
/// Applies the plain-language choices from the setup wizard to the underlying settings sections.
/// Each change goes through <see cref="Setting.Save{T}"/>, so it is validated and audited like any other.
/// </summary>
public static class SetupChoices
{
    public const string DeploymentRoleKey = "deployment_role";

    public static async Task<List<string>> ChooseInterfaces(DataContext dataContext, List<string> interfaceNames, string userEmail)
    {
        var captureSettings = await Setting.Load<CaptureSettings>(dataContext);
        captureSettings.InterfaceNames = interfaceNames;
        return await Setting.Save(dataContext, captureSettings, await Setting.GetRevision<CaptureSettings>(dataContext), userEmail);
    }

    public static async Task<List<string>> ChooseProtection(
        DataContext dataContext,
        ProtectionChoice protectionChoice,
        EnforcementProvider enforcementProvider,
        bool practiceMode,
        string? webhookUrl,
        string? webhookSecret,
        string userEmail)
    {
        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        responseSettings.Mode = protectionChoice switch
        {
            ProtectionChoice.BlockAutomatically => ResponseMode.Block,
            ProtectionChoice.SlowItDown => ResponseMode.Throttle,
            ProtectionChoice.BlockWhileAway => ResponseMode.BlockWhenIdle,
            _ => ResponseMode.WatchAndAlert
        };
        responseSettings.DryRun = practiceMode;

        var enforcementSettings = await Setting.Load<EnforcementSettings>(dataContext);
        enforcementSettings.Provider = protectionChoice == ProtectionChoice.JustTellMe ? EnforcementProvider.MonitorOnly : enforcementProvider;
        enforcementSettings.WebhookUrl = webhookUrl;
        enforcementSettings.WebhookSecret = webhookSecret;

        var errors = await Setting.Save(dataContext, enforcementSettings, await Setting.GetRevision<EnforcementSettings>(dataContext), userEmail);
        if (errors.Count > 0)
            return errors;

        return await Setting.Save(dataContext, responseSettings, await Setting.GetRevision<ResponseSettings>(dataContext), userEmail);
    }

    public static async Task<List<string>> ChooseAssistant(DataContext dataContext, AnalystSettings submittedSettings, string userEmail)
    {
        var analystSettings = await Setting.Load<AnalystSettings>(dataContext);
        analystSettings.Provider = submittedSettings.Provider;
        analystSettings.Enabled = submittedSettings.Provider != AnalystProvider.None;
        analystSettings.ApiKey = submittedSettings.ApiKey;
        analystSettings.OpenAiApiKey = submittedSettings.OpenAiApiKey;
        analystSettings.OpenRouterApiKey = submittedSettings.OpenRouterApiKey;

        if (!string.IsNullOrWhiteSpace(submittedSettings.OpenAiModel))
            analystSettings.OpenAiModel = submittedSettings.OpenAiModel.Trim();
        if (!string.IsNullOrWhiteSpace(submittedSettings.OpenRouterModel))
            analystSettings.OpenRouterModel = submittedSettings.OpenRouterModel.Trim();
        if (!string.IsNullOrWhiteSpace(submittedSettings.LocalEndpoint))
            analystSettings.LocalEndpoint = submittedSettings.LocalEndpoint.Trim();
        if (!string.IsNullOrWhiteSpace(submittedSettings.LocalModel))
            analystSettings.LocalModel = submittedSettings.LocalModel.Trim();

        var errors = await Setting.Save(dataContext, analystSettings, await Setting.GetRevision<AnalystSettings>(dataContext), userEmail);
        if (errors.Count == 0 && analystSettings.Enabled && !(await Setting.Load<AnalystSettings>(dataContext)).HasApiKey)
            errors.Add("Enter the API key for the assistant you chose, or choose \"Not now\".");

        return errors;
    }

    public static async Task<ProtectionChoice> CurrentProtection(DataContext dataContext)
    {
        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        return responseSettings.Mode switch
        {
            ResponseMode.Block => ProtectionChoice.BlockAutomatically,
            ResponseMode.Throttle => ProtectionChoice.SlowItDown,
            ResponseMode.BlockWhenIdle => ProtectionChoice.BlockWhileAway,
            _ => ProtectionChoice.JustTellMe
        };
    }
}
