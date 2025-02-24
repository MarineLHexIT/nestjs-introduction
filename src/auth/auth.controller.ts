import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthBody, AuthService } from 'src/auth/auth.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RequestWithUser } from 'src/auth/jwt.strategy';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/auth/dto/create-user.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ) {}

  // http://localhost:3000/auth/login
  @Post('login')
  async login(@Body() authBody: AuthBody) {
    return await this.authService.login(authBody);
  }

  @Post('register')
  async register(@Body() newUser: CreateUserDto) {
    return await this.authService.register(newUser);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  async auth(@Req() request: RequestWithUser) {
    return await this.userService.getUser({ userId: request.user.userId });
  }
}
