using MedVoll.Web.Data;
using MedVoll.Web.Interfaces;
using MedVoll.Web.Repositories;
using MedVoll.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using MedVoll.WebAPI.Services;
using MedVoll.WebAPI.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MedVoll.WebAPI.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var connectionString = builder.Configuration.GetConnectionString("SqliteConnection");
builder.Services.AddDbContext<ApplicationDbContext>(x => x.UseSqlite(connectionString));

builder.Services.AddIdentity<VollMedUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

////////////////////// Swagger //////////////////////
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

////////////////////// Repositories e Services //////////////////////
builder.Services.AddTransient<IMedicoRepository, MedicoRepository>();
builder.Services.AddTransient<IConsultaRepository, ConsultaRepository>();
builder.Services.AddTransient<IMedicoService, MedicoService>();
builder.Services.AddTransient<IConsultaService, ConsultaService>();
builder.Services.AddScoped<TokenJWTService>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
    opt => opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = builder.Configuration["JWTTokenConfiguration:Audience"],
        ValidIssuer = builder.Configuration["JWTTokenConfiguration:Issuer"],
        IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JWTKey:key"]!)),
    });
builder.Services.ConfigureSwagger();

builder.Services.AddAuthorization(auth => {
    auth.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    auth.AddPolicy("RH", policy => policy.RequireRole("RH"));
    auth.AddPolicy("Atendimento", policy => policy.RequireRole("Atendimento"));
    auth.AddPolicy("EditorDeMedicos", policy => 
    {
        policy.RequireAssertion(handler => handler.User.IsInRole("Admin")
            && handler.User.IsInRole("RH"));
    });

});

//Remover cabeçalho Server
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseHsts(); //HSTS = HTTP STRICT TRANSPORT SECURITY

app.UseAuthentication();

app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        await IdentitySeeder.SeedUsersAsync(services);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro ao executar o Seeder: {ex.Message}");
    }
}

app.MapControllers();
app.Run();
