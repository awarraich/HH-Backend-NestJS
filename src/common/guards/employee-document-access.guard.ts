import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { UserWithRolesInterface } from '../interfaces/user-with-roles.interface';
import { OrganizationRoleService } from '../../models/organizations/services/organization-role.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../models/employees/entities/employee.entity';

@Injectable()
export class EmployeeDocumentAccessGuard implements CanActivate {
  constructor(
    @Inject(forwardRef(() => OrganizationRoleService))
    private readonly organizationRoleService: OrganizationRoleService,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user: UserWithRolesInterface = request.user;
    const organizationId = request.params?.organizationId;
    const employeeId = request.params?.employeeId;

    if (!user?.userId) {
      throw new ForbiddenException('User not found');
    }
    if (!organizationId) {
      throw new ForbiddenException('Organization ID is required');
    }
    if (!employeeId) {
      throw new ForbiddenException('Employee ID is required');
    }

    const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(
      user.userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (hasRole) return true;

    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });
    if (employee?.user_id === user.userId) return true;

    throw new ForbiddenException(
      'You do not have permission to access this employee\'s documents.',
    );
  }
}
