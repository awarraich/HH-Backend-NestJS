import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import { SearchInterface } from '../interfaces/search.interface';

function toPageLimitString(v: unknown): string {
  return typeof v === 'string' || typeof v === 'number' ? String(v) : '';
}

@Injectable()
export class SearchPipe implements PipeTransform {
  transform(value: Record<string, unknown>, _metadata: ArgumentMetadata): SearchInterface {
    const query = value.query;
    const sort = value.sort;
    const defaultSort: SearchInterface['sort'] = { field: 'id', order: 'ASC' };
    return {
      query: typeof query === 'string' ? query : '',
      filters: (value.filters && typeof value.filters === 'object' && !Array.isArray(value.filters)
        ? value.filters
        : {}) as Record<string, unknown>,
      sort:
        sort &&
        typeof sort === 'object' &&
        'field' in sort &&
        'order' in sort &&
        typeof (sort as { field: unknown; order: unknown }).field === 'string' &&
        typeof (sort as { field: unknown; order: unknown }).order === 'string'
          ? (sort as SearchInterface['sort'])
          : defaultSort,
      pagination: {
        page: parseInt(toPageLimitString(value.page), 10) || 1,
        limit: parseInt(toPageLimitString(value.limit), 10) || 10,
      },
    };
  }
}
