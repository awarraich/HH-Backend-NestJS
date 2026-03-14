# Company Profile: Image Storage & URL Strategy

Same strategy for **local** and **live** server: only config (env) changes.

## Save flow (upload)

1. **Upload**  
   `POST .../company-profile/gallery/upload` (multipart, field `file`, optional `caption`, `category`).

2. **Storage** (`CompanyProfileStorageService`)  
   - **Local:** Write to `STORAGE_PATH/company-profile/{organizationId}/gallery/{uuid}.{ext}`.  
   - **S3:** `PutObject` with key `company-profile/{organizationId}/gallery/{uuid}.{ext}`.  
   Returns `{ file_name, file_path }` (relative path/key).

3. **Profile update**  
   Append to `profile.gallery`: `{ id: uuid, file_path, caption, category }`.  
   Same order as saved: **order of `gallery` array = display order**.  
   Logo and cover are stored as **paths** in `profile.logo` and `profile.cover_images[]` (same path format as gallery URLs).

4. **Response to client**  
   Upload returns `{ id, url }` where  
   `url = /v1/api/organizations/{orgId}/company-profile/media/gallery/{id}`  
   (path only; client adds base URL).

## Serve flow (read)

- **Authenticated:** `GET .../company-profile/media/:type/:fileId` → lookup by `fileId` (gallery/video item `id`), stream from `file_path` (local file or S3).
- **Public:** `GET .../company-profile/public-media/:type/:fileId` → same lookup and stream, no auth.

**Public profile response** (`getPublic`):  
Gallery and videos get **public-media** URLs. Logo and `cover_image`/`cover_images` are rewritten to **public-media** when they contain `/company-profile/media/`, so the same URL strategy works for all images (local and live).

## Order

- **Save:** Order of uploads and of `profile.gallery` / `profile.cover_images` is preserved.  
- **Show:** Use the same order when returning gallery and cover_images; do not reorder.

## Env (local vs live)

- **Local:** `STORAGE_TYPE=local`, `STORAGE_PATH=./storage` (or your path). Files under that path.
- **Live:** `STORAGE_TYPE=s3`, `S3_BUCKET_NAME`, etc. Same API and path format; only storage backend differs.

Frontend uses the **path** returned by the API and optionally prepends its API base URL (or relative path with proxy) so images work in both environments.
