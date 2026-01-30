import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { AuthService } from '../../authentication/services/auth.service';
import { RoleRepository } from '../../authentication/repositories/role.repository';
import { CreateUserByAdminDto } from './dto/create-user-by-admin.dto';
import { UpdateUserByAdminDto } from './dto/update-user-by-admin.dto';
import { QueryUsersDto } from './dto/query-users.dto';

@Controller('v1/api/admin/users')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class AdminsController {
  constructor(
    private readonly authService: AuthService,
    private readonly roleRepository: RoleRepository,
  ) {}

  @Get('roles')
  @HttpCode(HttpStatus.OK)
  async getRoles() {
    const roles = await this.roleRepository.findAllRoles();
    return SuccessHelper.createSuccessResponse(roles);
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async getUsers(@Query() queryDto: QueryUsersDto, @Request() req: any) {
    const adminUserId = req.user?.userId || req.user?.sub;
    const page = queryDto.page || 1;
    const limit = queryDto.limit || 20;
    const result = await this.authService.getAllUsersWithRoles(
      page,
      limit,
      queryDto.search,
      queryDto.roleId,
      adminUserId, // Exclude current admin user
    );
    return SuccessHelper.createPaginatedResponse(
      result.users,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getUserById(@Param('id') id: string) {
    const user = await this.authService.getUserByIdWithRoles(id);
    return SuccessHelper.createSuccessResponse(user);
  }

  @Post('create')
  @HttpCode(HttpStatus.CREATED)
  async createUser(@Body() createUserDto: CreateUserByAdminDto, @Request() req: any) {
    const adminUserId = req.user?.userId || req.user?.sub;
    const result = await this.authService.createUserByAdmin(createUserDto, adminUserId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserByAdminDto,
    @Request() req: any,
  ) {
    const adminUserId = req.user?.userId || req.user?.sub;
    const result = await this.authService.updateUserByAdmin(id, updateUserDto, adminUserId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteUser(@Param('id') id: string, @Request() req: any) {
    const adminUserId = req.user?.userId || req.user?.sub;
    const result = await this.authService.deleteUserByAdmin(id, adminUserId);
    return SuccessHelper.createSuccessResponse(result);
  }
}

