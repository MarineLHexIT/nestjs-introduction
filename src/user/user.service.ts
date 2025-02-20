import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async getUsers() {
    return this.prismaService.user.findMany({
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
      },
    });
  }

  async getUser({ userId }: { userId: string }) {
    return this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
      },
    });
  }
}
