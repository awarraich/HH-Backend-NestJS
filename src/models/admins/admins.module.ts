import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Admin } from './entities/admin.entity';
import { AdminProfile } from './entities/admin-profile.entity';
import { UserRole } from '../../authentication/entities/user-role.entity';
import { Role } from '../../authentication/entities/role.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { EmailModule } from '../../common/services/email/email.module';
import { AuditLogModule } from '../../common/services/audit/audit-log.module';
import { AdminsController } from './admins.controller';
import { AdminAuditLogsController } from './admin-audit-logs.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([Admin, AdminProfile, UserRole, Role]),
    AuthenticationModule,
    EmailModule,
    AuditLogModule,
  ],
  controllers: [AdminsController, AdminAuditLogsController],
  exports: [TypeOrmModule],
})
export class AdminsModule {}
