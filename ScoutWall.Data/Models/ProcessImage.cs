using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// A program (executable path) that has sent or received network traffic on this machine.
/// </summary>
[Table("process_images")]
[Index(nameof(ImagePath), IsUnique = true)]
public class ProcessImage : Repository<ProcessImage>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("image_path")]
    [MaxLength(1024)]
    public string ImagePath { get; set; } = string.Empty;

    [Column("name")]
    [MaxLength(256)]
    public string Name { get; set; } = string.Empty;

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    /// <summary>
    /// The description from the executable ("Google Chrome"), read by the sensor so people see names, not paths.
    /// </summary>
    [Column("friendly_name")]
    [MaxLength(256)]
    public string? FriendlyName { get; set; }

    [Column("publisher")]
    [MaxLength(256)]
    public string? Publisher { get; set; }

    /// <summary>
    /// Windows verified the publisher's signature, embedded in the file or through Microsoft's catalog of Windows
    /// files. When false, Publisher is only what the file claims.
    /// </summary>
    [Column("publisher_verified")]
    public bool PublisherVerified { get; set; }

    [Column("company")]
    [MaxLength(256)]
    public string? Company { get; set; }

    [Column("product_name")]
    [MaxLength(256)]
    public string? ProductName { get; set; }

    [Column("file_version")]
    [MaxLength(64)]
    public string? FileVersion { get; set; }

    [Column("identity_read_at")]
    public DateTime? IdentityReadAt { get; set; }

    [NotMapped]
    public bool IsNew => FirstSeenAt > DateTime.UtcNow.AddHours(-24);

    /// <summary>
    /// What to call the program in plain language.
    /// </summary>
    [NotMapped]
    public string DisplayName => !string.IsNullOrWhiteSpace(FriendlyName) ? FriendlyName!
        : !string.IsNullOrWhiteSpace(ProductName) ? ProductName!
        : System.IO.Path.GetFileNameWithoutExtension(Name);

    public static async Task<List<ProcessImage>> GetMissingIdentity(DataContext dataContext, int count)
    {
        var staleBefore = DateTime.UtcNow.AddDays(-1);
        return await Query(dataContext)
            .Where(processImage => processImage.IdentityReadAt == null || processImage.IdentityReadAt < staleBefore)
            .OrderByDescending(processImage => processImage.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task SaveIdentity(DataContext dataContext, long id, string? friendlyName, string? publisher, bool publisherVerified, string? company,
        string? productName, string? fileVersion)
    {
        await dataContext.ProcessImages
            .Where(processImage => processImage.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(processImage => processImage.FriendlyName, Limit(friendlyName))
                .SetProperty(processImage => processImage.Publisher, Limit(publisher))
                .SetProperty(processImage => processImage.PublisherVerified, publisherVerified)
                .SetProperty(processImage => processImage.Company, Limit(company))
                .SetProperty(processImage => processImage.ProductName, Limit(productName))
                .SetProperty(processImage => processImage.FileVersion, Limit(fileVersion, 64))
                .SetProperty(processImage => processImage.IdentityReadAt, DateTime.UtcNow));
    }

    private static string? Limit(string? value, int maximumLength = 256)
    {
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return null;

        return trimmed.Length <= maximumLength ? trimmed : trimmed[..maximumLength];
    }

    /// <summary>
    /// Returns the id of every path, creating rows for paths not seen before.
    /// </summary>
    public static async Task<Dictionary<string, long>> GetOrCreateIds(DataContext dataContext, IReadOnlyCollection<string> imagePaths, DateTime seenAt)
    {
        const string commandText = """
            INSERT INTO process_images (image_path, name, first_seen_at, last_seen_at)
            VALUES ($imagePath, $name, $seenAt, $seenAt)
            ON CONFLICT (image_path) DO UPDATE SET last_seen_at = excluded.last_seen_at;
            """;

        await ExecuteBatch(dataContext, commandText, imagePaths, (parameters, imagePath) =>
        {
            parameters.AddWithValue("$imagePath", imagePath);
            parameters.AddWithValue("$name", NameFromPath(imagePath));
            parameters.AddWithValue("$seenAt", seenAt);
        });

        var processImages = await GetAll(dataContext, processImage => imagePaths.Contains(processImage.ImagePath));
        return processImages.ToDictionary(processImage => processImage.ImagePath, processImage => processImage.Id);
    }

    public static string NameFromPath(string imagePath)
    {
        var fileName = Path.GetFileName(imagePath);
        return string.IsNullOrEmpty(fileName) ? imagePath : fileName;
    }
}
