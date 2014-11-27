using System;

namespace Thinktecture.IdentityServer.v3.AccessTokenValidation
{
	public class Clock : IClock
	{
		public DateTimeOffset UtcNow 
		{
			get { return DateTimeOffset.UtcNow; }
		}
	}
}