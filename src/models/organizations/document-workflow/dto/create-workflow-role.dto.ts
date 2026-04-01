import { IsString, IsNotEmpty, IsOptional, MaxLength } from 'class-validator';

export class CreateWorkflowRoleDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  name: string;

  @IsOptional()
  @IsString()
  description?: string;
}
