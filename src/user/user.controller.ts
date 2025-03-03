import { Controller, Get, Param } from '@nestjs/common';
import { UserService } from 'src/user/user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  async getUsers() {

    // Test Skeleton in the front
    await new Promise((r) => setTimeout(r, 2000));

    return this.userService.getUsers();
  }

  @Get(':userId')
  getUser(@Param('userId') userId: string) {
    return this.userService.getUser({ userId });
  }
}
