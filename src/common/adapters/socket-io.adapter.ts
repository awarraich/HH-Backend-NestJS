import { INestApplicationContext } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { Server, ServerOptions } from 'socket.io';

export class SocketIoAdapter extends IoAdapter {
  constructor(
    app: INestApplicationContext,
    private readonly wsPort: number,
    private readonly corsOrigins: string[] | false,
  ) {
    super(app);
  }

  createIOServer(port: number, options?: ServerOptions): Server {
    const actualPort = this.wsPort ?? port;
    return new Server(actualPort, {
      ...options,
      cors: {
        origin: this.corsOrigins,
        credentials: true,
      },
    });
  }
}
