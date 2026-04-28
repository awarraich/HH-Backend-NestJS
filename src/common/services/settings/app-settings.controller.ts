import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { RolesGuard } from '../../guards/roles.guard';
import { Roles } from '../../decorators/roles.decorator';
import { SuccessHelper } from '../../helpers/responses/success.helper';
import { AppSettingsService } from './app-settings.service';
import { UpsertSettingDto } from './dto/upsert-setting.dto';
import {
  DeleteLlmProviderQueryDto,
  GetSettingsQueryDto,
  LLM_PROVIDERS,
  SetLlmProviderDto,
} from './dto/llm-provider-setting.dto';

interface RequestWithUser {
  user?: { userId?: string; sub?: string };
}

const LLM_PROVIDER_KEY = 'llm.provider';

@Controller('v1/api/admin/settings')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('ADMIN')
export class AppSettingsController {
  constructor(private readonly settings: AppSettingsService) {}

  // ---- Typed helper for the LLM provider toggle (UI consumes this) -------

  @Get('llm-provider')
  @HttpCode(HttpStatus.OK)
  async getLlmProvider(@Query() query: GetSettingsQueryDto) {
    const all = await this.settings.listByKey(LLM_PROVIDER_KEY);
    const global = all.find((r) => r.scope === 'global') ?? null;
    const orgs = all.filter((r) => r.scope === 'organization');
    const filtered = query.organizationId
      ? orgs.filter((r) => r.organization_id === query.organizationId)
      : orgs;
    return SuccessHelper.createSuccessResponse({
      key: LLM_PROVIDER_KEY,
      supportedProviders: LLM_PROVIDERS,
      global: global
        ? { provider: global.value, updatedAt: global.updated_at, updatedBy: global.updated_by }
        : null,
      organizations: filtered.map((r) => ({
        organizationId: r.organization_id,
        provider: r.value,
        updatedAt: r.updated_at,
        updatedBy: r.updated_by,
      })),
    });
  }

  @Put('llm-provider')
  @HttpCode(HttpStatus.OK)
  async setLlmProvider(@Body() body: SetLlmProviderDto, @Request() req: RequestWithUser) {
    const userId = req.user?.userId ?? req.user?.sub;
    const saved = await this.settings.upsert({
      key: LLM_PROVIDER_KEY,
      scope: body.scope,
      organizationId: body.scope === 'organization' ? body.organizationId : null,
      value: body.provider,
      description:
        body.scope === 'global'
          ? 'Default LLM provider for all reasoning calls'
          : 'LLM provider override for this organization',
      updatedBy: userId,
    });
    return SuccessHelper.createSuccessResponse(saved, 'LLM provider updated');
  }

  @Delete('llm-provider')
  @HttpCode(HttpStatus.OK)
  async deleteLlmProvider(@Query() query: DeleteLlmProviderQueryDto) {
    await this.settings.delete(
      LLM_PROVIDER_KEY,
      query.scope,
      query.scope === 'organization' ? query.organizationId : null,
    );
    return SuccessHelper.createSuccessResponse(
      null,
      'LLM provider override removed; resolution falls back to next-most-specific scope',
    );
  }

  // ---- Generic key/value CRUD (extensible for future settings) -----------

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(@Query() query: GetSettingsQueryDto) {
    const rows = await this.settings.list(query.organizationId);
    return SuccessHelper.createSuccessResponse(rows);
  }

  @Get(':key')
  @HttpCode(HttpStatus.OK)
  async getByKey(@Param('key') key: string) {
    const rows = await this.settings.listByKey(key);
    return SuccessHelper.createSuccessResponse(rows);
  }

  @Put(':key')
  @HttpCode(HttpStatus.OK)
  async upsert(
    @Param('key') key: string,
    @Body() body: UpsertSettingDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    const saved = await this.settings.upsert({
      key,
      scope: body.scope,
      organizationId: body.scope === 'organization' ? body.organizationId : null,
      value: body.value,
      description: body.description,
      updatedBy: userId,
    });
    return SuccessHelper.createSuccessResponse(saved, 'Setting saved');
  }

  @Delete(':key')
  @HttpCode(HttpStatus.OK)
  async delete(@Param('key') key: string, @Query() query: DeleteLlmProviderQueryDto) {
    await this.settings.delete(
      key,
      query.scope,
      query.scope === 'organization' ? query.organizationId : null,
    );
    return SuccessHelper.createSuccessResponse(null, 'Setting removed');
  }
}
