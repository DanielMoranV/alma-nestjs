import {
  createParamDecorator,
  ExecutionContext,
  InternalServerErrorException,
} from '@nestjs/common';
import { FastifyRequest } from 'fastify';

export const GetUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<FastifyRequest>();
    const user = request.user;

    if (!user) {
      // Esto solo debería ocurrir si el JwtGuard no se aplicó correctamente
      // o si hay un problema grave en la autenticación.
      throw new InternalServerErrorException(
        'User not found in request. Make sure JwtGuard is applied.',
      );
    }

    return user;
  },
);
