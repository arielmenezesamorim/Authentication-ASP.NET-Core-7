using Domain.Interfaces.IServices.Security;
using Domain.Services.Security;

namespace AutheticationAPI.Configuration
{
    public static class DependecyInjectionConfig
    {
        public static IServiceCollection ResolveDependencies(this IServiceCollection services)
        {
            // Gosto sempre de separar por categorias para manter uma organização limpa

            // Interface and Repository Generics

            // Other Interface and Repository

            // Service Security
            services.AddTransient<IAuthService, AuthService>();

            // Other Service


            return services;
        }
    }
}
