import { Controller, Get, Query, HttpCode, HttpStatus } from '@nestjs/common';
import { JobManagementService } from './job-management.service';
import { QueryJobPostingDto } from './dto/query-job-posting.dto';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';

/**
 * Public careers API – same URL structure as blogs: /v1/api/careers.
 * Use this URL for the careers tab. Returns active job postings.
 */
@Controller('v1/api/careers')
export class CareersController {
  constructor(private readonly jobManagementService: JobManagementService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(@Query() query: QueryJobPostingDto): Promise<unknown> {
    const result = await this.jobManagementService.findAllActive({
      search: query.search,
      page: query.page ?? 1,
      limit: query.limit ?? 100,
    });
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }
}
