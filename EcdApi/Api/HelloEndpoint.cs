using FastEndpoints;

namespace EcdApi.Api
{
    public class HelloEndpoint : EndpointWithoutRequest<string>
    {
        public override void Configure()
        {
            Get("/api/v1/hello");
            AllowAnonymous();
        }

        public override Task HandleAsync(CancellationToken ct)
        {
            return SendAsync(DateTime.Now.ToLongDateString(), 200, ct);
        }
    }
}
