using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// "Always allow" from the program tables: adds or removes a program's full path on the never-block allowlist
/// and lifts any block on it. Allowlists change only through forms, never through chat.
/// </summary>
public static class ProgramAllowlist
{
    public static async Task<string?> Allow(DataContext dataContext, long processImageId, string userEmail)
    {
        var (imagePath, error) = await FindPath(dataContext, processImageId);
        if (imagePath == null)
            return error;

        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        if (!responseSettings.IsAllowlistedProgram(imagePath))
        {
            // Outside Windows and Program Files anyone can overwrite the file, so the allowance is tied to its contents.
            if (!TrustedPaths.IsInProtectedFolder(imagePath))
            {
                var fileHash = ProgramFileHash.Compute(imagePath);
                if (fileHash == null)
                    return "ScoutWall couldn't read that program's file, so it can't be allowed safely.";

                responseSettings.AllowlistedProgramHashes.Remove(responseSettings.AllowlistedProgramHashes.Keys.FirstOrDefault(key => string.Equals(key, imagePath, StringComparison.OrdinalIgnoreCase)) ?? imagePath);
                responseSettings.AllowlistedProgramHashes[imagePath] = fileHash;
            }

            if (!responseSettings.AllowlistedPrograms.Contains(imagePath, StringComparer.OrdinalIgnoreCase))
                responseSettings.AllowlistedPrograms.Add(imagePath);

            var errors = await Setting.Save(dataContext, responseSettings, await Setting.GetRevision<ResponseSettings>(dataContext), userEmail);
            if (errors.Count > 0)
                return string.Join(" ", errors);
        }

        var liftedBlocks = await dataContext.ResponseActions
            .Where(action => (action.ActionType == ResponseActionType.BlockProgram || action.ActionType == ResponseActionType.ThrottleProgram)
                && action.Target == imagePath
                && (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active || action.Status == ResponseActionStatus.Simulated))
            .ToListAsync();
        foreach (var liftedBlock in liftedBlocks)
            await ResponseAction.Revoke(dataContext, liftedBlock.Id, userEmail);

        return null;
    }

    public static async Task<string?> Remove(DataContext dataContext, long processImageId, string userEmail)
    {
        var (imagePath, error) = await FindPath(dataContext, processImageId);
        if (imagePath == null)
            return error;

        // The built-in entries (svchost, Defender, ScoutWall and so on) are not removable from a table row.
        if (ProtectedPrograms.ReasonNotBlockable(imagePath) != null)
            return "That program is protected by ScoutWall and stays allowed.";

        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        var removedCount = responseSettings.AllowlistedPrograms.RemoveAll(entry => string.Equals(entry, imagePath, StringComparison.OrdinalIgnoreCase));
        foreach (var pinnedPath in responseSettings.AllowlistedProgramHashes.Keys.Where(key => string.Equals(key, imagePath, StringComparison.OrdinalIgnoreCase)).ToList())
            responseSettings.AllowlistedProgramHashes.Remove(pinnedPath);

        if (removedCount == 0)
            return null;

        var errors = await Setting.Save(dataContext, responseSettings, await Setting.GetRevision<ResponseSettings>(dataContext), userEmail);
        return errors.Count > 0 ? string.Join(" ", errors) : null;
    }

    private static async Task<(string? ImagePath, string? Error)> FindPath(DataContext dataContext, long processImageId)
    {
        var processImage = await ProcessImage.Get(dataContext, image => image.Id == processImageId);
        if (processImage == null)
            return (null, "That program is no longer known to ScoutWall.");

        var imagePath = ProtectedPrograms.Normalize(processImage.ImagePath);
        return imagePath == null ? (null, "ScoutWall doesn't know where that program is installed, so it can't be added to the allowlist.") : (imagePath, null);
    }
}
