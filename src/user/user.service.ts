import { Injectable } from '@nestjs/common';

@Injectable()
export class UserService {
  getUsers() {
    return [
      {
        id: 1,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@doe.com',
        password: '123456',
      },
    ];
  }
}
