using Login.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie()
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
})
.AddOAuth("LinkedIn", options =>
{
    options.ClientId = builder.Configuration["Authentication:LinkedIn:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:LinkedIn:ClientSecret"]!;
    options.CallbackPath = "/signin-linkedin";

    options.AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
    options.TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
    options.UserInformationEndpoint = "https://api.linkedin.com/v2/me";

    options.Scope.Add("r_liteprofile");
    options.Scope.Add("r_emailaddress");

    options.ClaimActions.MapJsonKey("urn:linkedin:id", "id");
    options.ClaimActions.MapJsonKey("urn:linkedin:firstName", "localizedFirstName");
    options.ClaimActions.MapJsonKey("urn:linkedin:lastName", "localizedLastName");

    options.Events = new OAuthEvents
    {
        OnCreatingTicket = async context =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get,
                "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))");

            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.AccessToken);
            var response = await context.Backchannel.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var payload = Newtonsoft.Json.Linq.JObject.Parse(await response.Content.ReadAsStringAsync());
                var email = payload["elements"]?[0]?["handle~"]?["emailAddress"]?.ToString();
                if (email != null)
                {
                    context.Identity.AddClaim(new System.Security.Claims.Claim("email", email));
                }
            }
        }
    };
})
.AddFacebook(options =>
{
    options.AppId = builder.Configuration["Authentication:Facebook:AppId"]!;
    options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"]!;
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
