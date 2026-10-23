using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting.Systemd;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.FileProviders;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Filters;
using ScoutWall.Models;

namespace ScoutWall;

/// <summary>
/// "scoutwall web": the web console. Owns the database schema (applies migrations at start). Installed as a service
/// listening on http://localhost:5215 only.
/// </summary>
public static class WebConsole
{
    public const string ServiceName = "ScoutWall Web";

    public static async Task<int> RunAsync(string[] args)
    {
        // Installed (as a service, or as the single-file executable) the content root is where the executable's files are;
        // from Visual Studio it is the project folder.
        var runsInstalled = WindowsServiceHelpers.IsWindowsService() || SystemdHelpers.IsSystemdService() || string.IsNullOrEmpty(typeof(WebConsole).Assembly.Location);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = runsInstalled ? AppContext.BaseDirectory : default
        });
        builder.Host.UseWindowsService(options => options.ServiceName = ServiceName);
        builder.Host.UseSystemd();
        if (OperatingSystem.IsWindows())
            WebHosting.UseServiceEventSource(builder.Services);
        var databasePath = DataContext.ResolveDatabasePath(builder.Configuration["Database:Path"]);

        builder.Services.AddDbContext<DataContext>(options => DataContext.Configure(options, databasePath));

        // Sign-in cookies are encrypted with keys kept next to the database, so sessions survive restarts and the
        // Visual Studio and service copies of the console can share them.
        var keyDirectory = new DirectoryInfo(Path.Combine(Path.GetDirectoryName(databasePath)!, "keys"));
        var dataProtection = builder.Services.AddDataProtection().SetApplicationName("ScoutWall").PersistKeysToFileSystem(keyDirectory);
        if (OperatingSystem.IsWindows())
            dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);

        builder.Services.AddControllersWithViews(options =>
        {
            // Every page requires a signed-in user unless it opts out with [AllowAnonymous].
            options.Filters.Add(new AuthorizeFilter(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()));
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            options.Filters.Add(new SetupRequiredFilter());
            options.Filters.Add(new RequirePasswordChangeFilter());
        });

        builder.Services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/Logout";
                options.AccessDeniedPath = "/Account/Login";
                options.Cookie.Name = "ScoutWall.Session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = true;
                options.Events.OnValidatePrincipal = UserSession.Validate;
            });

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("login", httpContext => RateLimitPartition.GetFixedWindowLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
        });

        var app = builder.Build();

        await DataContext.Initialize(databasePath);

        // The console normally listens on http://localhost only; HTTPS redirection and HSTS need an https address.
        var servesHttps = (app.Configuration["Urls"] ?? string.Empty).Contains("https://", StringComparison.OrdinalIgnoreCase);

        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Dashboard/Error");
            if (servesHttps)
                app.UseHsts();
        }

        app.Use(async (httpContext, next) =>
        {
            var headers = httpContext.Response.Headers;
            headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'";
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            headers.XFrameOptions = "DENY";
            await next();
        });

        if (servesHttps)
            app.UseHttpsRedirection();

        // Styles, scripts and images are built into the program, so the single-file executable needs nothing beside
        // it. During development they are served straight from the project's wwwroot folder instead.
        if (!app.Environment.IsDevelopment())
            app.Environment.WebRootFileProvider = new ManifestEmbeddedFileProvider(typeof(WebConsole).Assembly, "wwwroot");
        app.UseStaticFiles(new StaticFileOptions { FileProvider = app.Environment.WebRootFileProvider });
        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        await app.RunAsync();
        return 0;
    }
}

/// <summary>
/// Logs to the event source registered for the service; the default source is not registered and a failed
/// event log write would stop the host.
/// </summary>
internal static class WebHosting
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static void UseServiceEventSource(IServiceCollection services)
    {
        services.Configure<Microsoft.Extensions.Logging.EventLog.EventLogSettings>(settings => settings.SourceName = WebConsole.ServiceName);
    }
}
