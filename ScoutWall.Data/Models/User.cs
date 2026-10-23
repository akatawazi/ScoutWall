using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

[Table("users")]
[Index(nameof(NormalizedEmail), IsUnique = true)]
public class User : Repository<User>
{
    public const int MinimumPasswordLength = 10;
    private const int MaximumFailedLogins = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly PasswordHasher<User> PasswordHasher = new();

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("email")]
    [MaxLength(256)]
    public string Email { get; set; } = string.Empty;

    [Column("normalized_email")]
    [MaxLength(256)]
    public string NormalizedEmail { get; set; } = string.Empty;

    [Column("display_name")]
    [MaxLength(256)]
    public string DisplayName { get; set; } = string.Empty;

    [Column("password_hash")]
    public string PasswordHash { get; set; } = string.Empty;

    [Column("must_change_password")]
    public bool MustChangePassword { get; set; }

    [Column("failed_login_count")]
    public int FailedLoginCount { get; set; }

    [Column("locked_until")]
    public DateTime? LockedUntil { get; set; }

    [Column("last_login_at")]
    public DateTime? LastLoginAt { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("updated_at")]
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Stored in the sign-in cookie. Changes with the password, so a password change or a removed account
    /// ends every existing session on the next request.
    /// </summary>
    public string SessionStamp()
    {
        var stampBytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{Id}:{PasswordHash}"));
        return Convert.ToHexString(stampBytes, 0, 16);
    }

    public static string NormalizeEmail(string email)
    {
        return email.Trim().ToUpperInvariant();
    }

    public static async Task<User?> GetByEmail(DataContext dataContext, string email)
    {
        var normalizedEmail = NormalizeEmail(email);
        return await Get(dataContext, user => user.NormalizedEmail == normalizedEmail);
    }

    public static async Task<List<User>> GetAllOrdered(DataContext dataContext)
    {
        return await Query(dataContext).OrderBy(user => user.Email).ToListAsync();
    }

    /// <summary>
    /// Adds a user with a temporary password that must be changed at first login. Returns an error or null.
    /// </summary>
    public static async Task<string?> Create(DataContext dataContext, string? email, string? temporaryPassword, string createdBy)
    {
        email ??= string.Empty;
        temporaryPassword ??= string.Empty;
        if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
            return "Enter a valid email address.";

        if (temporaryPassword.Length < MinimumPasswordLength)
            return $"The temporary password must be at least {MinimumPasswordLength} characters.";

        if (await GetByEmail(dataContext, email) != null)
            return "A user with that email already exists.";

        var user = new User
        {
            Email = email.Trim(),
            NormalizedEmail = NormalizeEmail(email),
            DisplayName = email.Trim(),
            MustChangePassword = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        user.PasswordHash = PasswordHasher.HashPassword(user, temporaryPassword);
        await Insert(dataContext, user);
        await AuditEntry.Record(dataContext, createdBy, "User created", user.Email);
        return null;
    }

    /// <summary>
    /// Creates the first administrator during setup. The check and the insert run in one write transaction,
    /// so only one of two simultaneous attempts can succeed. Returns an error or null.
    /// </summary>
    public static async Task<string?> CreateFirstAdministrator(DataContext dataContext, string? email, string? password)
    {
        email ??= string.Empty;
        password ??= string.Empty;
        if (!new EmailAddressAttribute().IsValid(email))
            return "Enter a valid email address.";

        if (password.Length < MinimumPasswordLength)
            return $"Choose a password of at least {MinimumPasswordLength} characters.";

        await using var transaction = await dataContext.Database.BeginTransactionAsync();
        if (await dataContext.Users.AnyAsync())
            return "An administrator already exists. Sign in instead.";

        var user = new User
        {
            Email = email.Trim(),
            NormalizedEmail = NormalizeEmail(email),
            DisplayName = email.Trim(),
            MustChangePassword = false,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        user.PasswordHash = PasswordHasher.HashPassword(user, password);
        dataContext.Users.Add(user);
        await dataContext.SaveChangesAsync();
        await transaction.CommitAsync();
        dataContext.ChangeTracker.Clear();

        await AuditEntry.Record(dataContext, user.Email, "Administrator created during setup", user.Email);
        return null;
    }

    public static async Task<bool> AnyExist(DataContext dataContext)
    {
        return await dataContext.Users.AnyAsync();
    }

    public static async Task<string?> Remove(DataContext dataContext, long id, string removedBy)
    {
        var user = await Get(dataContext, item => item.Id == id);
        if (user == null)
            return "User not found.";

        if (user.NormalizedEmail == NormalizeEmail(removedBy))
            return "You cannot remove your own account.";

        await Delete(dataContext, user);
        await AuditEntry.Record(dataContext, removedBy, "User removed", user.Email);
        return null;
    }

    public static async Task<LoginResult> Authenticate(DataContext dataContext, string email, string password)
    {
        var user = await GetByEmail(dataContext, email);
        if (user == null)
        {
            // Hash anyway so response time does not reveal whether the account exists.
            PasswordHasher.HashPassword(new User(), password);
            return new LoginResult(LoginOutcome.InvalidCredentials, null);
        }

        if (user.IsLockedOut(DateTime.UtcNow))
            return new LoginResult(LoginOutcome.LockedOut, null);

        if (!user.VerifyPassword(password))
        {
            await user.RecordFailedLogin(dataContext);
            return new LoginResult(LoginOutcome.InvalidCredentials, null);
        }

        await user.RecordSuccessfulLogin(dataContext);
        return new LoginResult(LoginOutcome.Succeeded, user);
    }

    public bool IsLockedOut(DateTime now)
    {
        return LockedUntil.HasValue && LockedUntil.Value > now;
    }

    public async Task<string?> ChangePassword(DataContext dataContext, string currentPassword, string newPassword)
    {
        if (!VerifyPassword(currentPassword))
            return "The current password is incorrect.";

        if (newPassword.Length < MinimumPasswordLength)
            return $"The new password must be at least {MinimumPasswordLength} characters.";

        if (newPassword == currentPassword)
            return "The new password must be different from the current password.";

        PasswordHash = PasswordHasher.HashPassword(this, newPassword);
        MustChangePassword = false;
        UpdatedAt = DateTime.UtcNow;
        await Update(dataContext, this);
        return null;
    }

    private bool VerifyPassword(string password)
    {
        var verificationResult = PasswordHasher.VerifyHashedPassword(this, PasswordHash, password);
        return verificationResult != PasswordVerificationResult.Failed;
    }

    private async Task RecordFailedLogin(DataContext dataContext)
    {
        FailedLoginCount++;
        if (FailedLoginCount >= MaximumFailedLogins)
        {
            LockedUntil = DateTime.UtcNow.Add(LockoutDuration);
            FailedLoginCount = 0;
        }

        UpdatedAt = DateTime.UtcNow;
        await Update(dataContext, this);
    }

    private async Task RecordSuccessfulLogin(DataContext dataContext)
    {
        FailedLoginCount = 0;
        LockedUntil = null;
        LastLoginAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
        await Update(dataContext, this);
    }
}

public record LoginResult(LoginOutcome Outcome, User? User);
