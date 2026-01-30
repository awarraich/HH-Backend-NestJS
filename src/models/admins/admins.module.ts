import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Admin } from './entities/admin.entity';
import { AdminProfile } from './entities/admin-profile.entity';
import { UserRole } from '../../authentication/entities/user-role.entity';
import { Role } from '../../authentication/entities/role.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { EmailModule } from '../../common/services/email/email.module';
import { AdminsController } from './admins.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([Admin, AdminProfile, UserRole, Role]),
    AuthenticationModule,
    EmailModule,
  ],
  controllers: [AdminsController],
  exports: [TypeOrmModule],
})
export class AdminsModule {}
