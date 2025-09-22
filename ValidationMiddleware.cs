using System;

namespace SafeVault;

public class ValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ValidationMiddleware> _logger;

    public ValidationMiddleware(RequestDelegate next, ILogger<ValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Validate content length
        if (context.Request.ContentLength > 1024 * 1024) // 1MB limit
        {
            _logger.LogWarning("Request rejected: Content length exceeds maximum allowed size");
            context.Response.StatusCode = 413;
            await context.Response.WriteAsync("Request entity too large");
            return;
        }

        // Validate content type for POST requests
        if (context.Request.Method == "POST" && 
            !context.Request.ContentType?.StartsWith("application/json") == true)
        {
            _logger.LogWarning("Request rejected: Invalid content type");
            context.Response.StatusCode = 415;
            await context.Response.WriteAsync("Unsupported media type");
            return;
        }

        await _next(context);
    }
}
