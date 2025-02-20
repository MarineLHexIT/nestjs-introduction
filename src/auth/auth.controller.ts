import { Body, Controller, Post } from '@nestjs/common';
import { AuthBody, AuthService } from 'src/auth/auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // http://localhost:3000/auth/login
  @Post('login')
  async login(@Body() authBody: AuthBody) {
    return await this.authService.authenticate(authBody);
  }
}
