using MedVoll.Web.Dtos;
using MedVoll.WebAPI.Dtos;
using MedVoll.WebAPI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> userManager;
    private readonly SignInManager<IdentityUser> signInManager;
    private readonly TokenJWTService tokenJWTService;

    public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, TokenJWTService tokenJWTService)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.tokenJWTService = tokenJWTService;
    }

    //Endpoints
    [HttpPost("registrar-usuario")]
    public async Task<IActionResult> RegistrarUsuarioAsync([FromBody] UsuarioDto usuarioDto)
    {
        var usuarioReg = await userManager.FindByEmailAsync(usuarioDto.Email!);
        if (usuarioReg is not null)
        {
            return BadRequest("Usuário já foi registrado na base de dados.");
        }

        var usuario = new IdentityUser
        {
            UserName = usuarioDto.Email,
            Email = usuarioDto.Email,
            EmailConfirmed = true
        };
        var result = await userManager.CreateAsync(usuario, usuarioDto.Senha);
        if (!result.Succeeded)
        {
            return BadRequest($"Falha ao registrar usuário : {result.Errors}");
        }
        await signInManager.SignInAsync(usuario, isPersistent: false);

        return Ok(new { Mensagem = "Usuário registrado com sucesso",
            Token = tokenJWTService.GerarTokenDeUsuario(usuarioDto)
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync([FromBody] UsuarioDto usuarioDto)
    {
        var result = await signInManager.PasswordSignInAsync(usuarioDto.Email!, usuarioDto.Senha!, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return BadRequest("Falha no login do usuário.");
        }

        UsuarioTokenDto usuarioTokenDto = tokenJWTService.GerarTokenDeUsuario(usuarioDto);
        var refreshToken = tokenJWTService.GerarRefreshToken();
        usuarioTokenDto.RefreshToken = refreshToken;

        return base.Ok(new
        {
            Mensagem = "Usuário logado com sucesso",
            Token = usuarioTokenDto
        });
    }

}