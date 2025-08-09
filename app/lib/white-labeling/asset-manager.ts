/**
 * Asset Manager for iSECTECH Protect White-Labeling
 * Production-grade asset management system with security, optimization, and CDN integration
 */

import crypto from 'crypto';
import type { 
  BrandAsset, 
  AssetType, 
  AssetFormat, 
  AssetUploadRequest,
  SUPPORTED_ASSET_FORMATS,
  MAX_ASSET_SIZES
} from '@/types/white-labeling';

export interface AssetProcessingOptions {
  maxWidth?: number;
  maxHeight?: number;
  quality?: number; // 1-100
  format?: AssetFormat;
  optimize?: boolean;
}

export interface AssetValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  metadata: {
    width: number;
    height: number;
    fileSize: number;
    format: string;
    hasTransparency?: boolean;
  };
}

export class AssetManager {
  private static instance: AssetManager;
  private assetCache = new Map<string, BrandAsset>();
  private processingQueue = new Map<string, Promise<BrandAsset>>();
  
  private constructor() {}

  public static getInstance(): AssetManager {
    if (!AssetManager.instance) {
      AssetManager.instance = new AssetManager();
    }
    return AssetManager.instance;
  }

  /**
   * Upload and process brand asset
   */
  public async uploadAsset(
    request: AssetUploadRequest,
    tenantId: string,
    userId: string,
    options?: AssetProcessingOptions
  ): Promise<BrandAsset> {
    // Generate unique processing ID
    const processingId = this.generateProcessingId(request.file, tenantId);
    
    // Check if already processing
    if (this.processingQueue.has(processingId)) {
      return this.processingQueue.get(processingId)!;
    }

    // Start processing
    const processingPromise = this.processAssetUpload(request, tenantId, userId, options);
    this.processingQueue.set(processingId, processingPromise);

    try {
      const result = await processingPromise;
      this.processingQueue.delete(processingId);
      return result;
    } catch (error) {
      this.processingQueue.delete(processingId);
      throw error;
    }
  }

  /**
   * Validate asset before upload
   */
  public async validateAsset(file: File, type: AssetType): Promise<AssetValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check file size
    const maxSize = MAX_ASSET_SIZES[type];
    if (file.size > maxSize) {
      errors.push(`File size (${this.formatFileSize(file.size)}) exceeds maximum allowed size (${this.formatFileSize(maxSize)})`);
    }

    // Check file format
    const fileExtension = this.getFileExtension(file.name).toLowerCase() as AssetFormat;
    const supportedFormats = SUPPORTED_ASSET_FORMATS[type];
    if (!supportedFormats.includes(fileExtension)) {
      errors.push(`File format '${fileExtension}' is not supported for ${type}. Supported formats: ${supportedFormats.join(', ')}`);
    }

    // Get image metadata
    const metadata = await this.getImageMetadata(file);
    
    // Validate dimensions based on asset type
    const dimensionValidation = this.validateDimensions(type, metadata.width, metadata.height);
    errors.push(...dimensionValidation.errors);
    warnings.push(...dimensionValidation.warnings);

    // Security validation
    const securityValidation = await this.validateAssetSecurity(file);
    errors.push(...securityValidation.errors);
    warnings.push(...securityValidation.warnings);

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      metadata: {
        width: metadata.width,
        height: metadata.height,
        fileSize: file.size,
        format: fileExtension,
        hasTransparency: metadata.hasTransparency,
      },
    };
  }

  /**
   * Optimize asset for web delivery
   */
  public async optimizeAsset(
    file: File,
    type: AssetType,
    options: AssetProcessingOptions = {}
  ): Promise<{ optimizedFile: Blob; metadata: any }> {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas context not available');

    // Load image
    const img = await this.loadImage(file);
    
    // Calculate optimal dimensions
    const { width, height } = this.calculateOptimalDimensions(
      img.width,
      img.height,
      type,
      options
    );

    // Set canvas dimensions
    canvas.width = width;
    canvas.height = height;

    // Draw optimized image
    ctx.drawImage(img, 0, 0, width, height);

    // Convert to optimized blob
    const quality = options.quality ? options.quality / 100 : 0.85;
    const outputFormat = options.format || this.getOptimalFormat(type, file.type);
    
    return new Promise((resolve, reject) => {
      canvas.toBlob(
        (blob) => {
          if (!blob) {
            reject(new Error('Failed to optimize image'));
            return;
          }
          
          resolve({
            optimizedFile: blob,
            metadata: {
              originalSize: file.size,
              optimizedSize: blob.size,
              compressionRatio: ((file.size - blob.size) / file.size * 100).toFixed(1),
              dimensions: { width, height },
              format: outputFormat,
            },
          });
        },
        `image/${outputFormat}`,
        quality
      );
    });
  }

  /**
   * Generate responsive image variants
   */
  public async generateResponsiveVariants(
    asset: BrandAsset,
    sizes: { name: string; width: number; height?: number }[]
  ): Promise<{ name: string; url: string; dimensions: { width: number; height: number } }[]> {
    const variants: { name: string; url: string; dimensions: { width: number; height: number } }[] = [];
    
    for (const size of sizes) {
      try {
        // Load original image
        const response = await fetch(asset.url);
        const blob = await response.blob();
        const file = new File([blob], asset.name, { type: blob.type });

        // Generate variant
        const optimized = await this.optimizeAsset(asset.type, file, {
          maxWidth: size.width,
          maxHeight: size.height,
          quality: 85,
          optimize: true,
        });

        // Upload variant (mock - would integrate with storage service)
        const variantUrl = await this.uploadToStorage(
          optimized.optimizedFile,
          `${asset.id}/${size.name}`,
          asset.tenantId
        );

        variants.push({
          name: size.name,
          url: variantUrl,
          dimensions: optimized.metadata.dimensions,
        });
      } catch (error) {
        console.error(`Failed to generate variant ${size.name}:`, error);
      }
    }

    return variants;
  }

  /**
   * Generate asset thumbnails
   */
  public async generateThumbnail(asset: BrandAsset): Promise<string> {
    const response = await fetch(asset.url);
    const blob = await response.blob();
    const file = new File([blob], asset.name, { type: blob.type });

    const optimized = await this.optimizeAsset(asset.type, file, {
      maxWidth: 200,
      maxHeight: 200,
      quality: 70,
      format: 'webp',
    });

    return this.uploadToStorage(
      optimized.optimizedFile,
      `${asset.id}/thumbnail`,
      asset.tenantId
    );
  }

  /**
   * Delete asset and all variants
   */
  public async deleteAsset(assetId: string, tenantId: string): Promise<void> {
    // Remove from cache
    this.assetCache.delete(assetId);

    // Delete from storage (mock - would integrate with storage service)
    await this.deleteFromStorage(assetId, tenantId);
  }

  /**
   * Get asset with caching
   */
  public async getAsset(assetId: string, tenantId: string): Promise<BrandAsset | null> {
    // Check cache first
    const cacheKey = `${tenantId}:${assetId}`;
    if (this.assetCache.has(cacheKey)) {
      return this.assetCache.get(cacheKey)!;
    }

    // Fetch from database/storage (mock implementation)
    const asset = await this.fetchAssetFromDatabase(assetId, tenantId);
    
    if (asset) {
      this.assetCache.set(cacheKey, asset);
    }

    return asset;
  }

  /**
   * Generate secure asset URLs with expiration
   */
  public generateSecureUrl(
    asset: BrandAsset,
    expiresIn: number = 3600 // 1 hour
  ): string {
    const expires = Math.floor(Date.now() / 1000) + expiresIn;
    const signature = this.generateUrlSignature(asset.url, expires, asset.tenantId);
    
    const url = new URL(asset.url);
    url.searchParams.set('expires', expires.toString());
    url.searchParams.set('signature', signature);
    url.searchParams.set('tenant', asset.tenantId);
    
    return url.toString();
  }

  /**
   * Bulk asset operations
   */
  public async bulkUpload(
    requests: AssetUploadRequest[],
    tenantId: string,
    userId: string,
    onProgress?: (completed: number, total: number) => void
  ): Promise<{ successful: BrandAsset[]; failed: { request: AssetUploadRequest; error: string }[] }> {
    const successful: BrandAsset[] = [];
    const failed: { request: AssetUploadRequest; error: string }[] = [];

    for (let i = 0; i < requests.length; i++) {
      try {
        const asset = await this.uploadAsset(requests[i], tenantId, userId);
        successful.push(asset);
      } catch (error) {
        failed.push({
          request: requests[i],
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }

      if (onProgress) {
        onProgress(i + 1, requests.length);
      }
    }

    return { successful, failed };
  }

  // Private helper methods

  private async processAssetUpload(
    request: AssetUploadRequest,
    tenantId: string,
    userId: string,
    options?: AssetProcessingOptions
  ): Promise<BrandAsset> {
    // Validate asset
    const validation = await this.validateAsset(request.file, request.type);
    if (!validation.isValid) {
      throw new Error(`Asset validation failed: ${validation.errors.join(', ')}`);
    }

    // Optimize asset
    const optimized = await this.optimizeAsset(request.file, request.type, options);

    // Generate unique ID and version
    const assetId = this.generateAssetId();
    const version = this.generateVersion();

    // Upload to storage
    const url = await this.uploadToStorage(optimized.optimizedFile, assetId, tenantId);
    const thumbnailUrl = await this.generateThumbnailUrl(optimized.optimizedFile, assetId, tenantId);

    // Create asset record
    const asset: BrandAsset = {
      id: assetId,
      name: request.name,
      type: request.type,
      format: this.getFileExtension(request.file.name) as AssetFormat,
      url,
      thumbnailUrl,
      fileSize: optimized.optimizedFile.size,
      dimensions: validation.metadata,
      metadata: request.metadata || {},
      version,
      isActive: true,
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    // Save to database (mock implementation)
    await this.saveAssetToDatabase(asset);

    // Cache the asset
    this.assetCache.set(`${tenantId}:${assetId}`, asset);

    return asset;
  }

  private validateDimensions(
    type: AssetType,
    width: number,
    height: number
  ): { errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    const requirements = {
      'logo-primary': { minWidth: 120, maxWidth: 800, minHeight: 40, maxHeight: 200, aspectRatio: [1, 5] },
      'logo-secondary': { minWidth: 80, maxWidth: 400, minHeight: 20, maxHeight: 100, aspectRatio: [1, 8] },
      'favicon': { minWidth: 16, maxWidth: 512, minHeight: 16, maxHeight: 512, square: true },
      'email-header': { minWidth: 200, maxWidth: 600, minHeight: 50, maxHeight: 150 },
      'report-header': { minWidth: 300, maxWidth: 1200, minHeight: 60, maxHeight: 300 },
      'mobile-icon': { minWidth: 72, maxWidth: 512, minHeight: 72, maxHeight: 512, square: true },
      'background': { minWidth: 800, maxWidth: 4000, minHeight: 600, maxHeight: 3000 },
      'watermark': { minWidth: 100, maxWidth: 500, minHeight: 100, maxHeight: 500 },
    };

    const req = requirements[type];
    if (!req) return { errors, warnings };

    if (width < req.minWidth || height < req.minHeight) {
      errors.push(`Image too small. Minimum size: ${req.minWidth}x${req.minHeight}px`);
    }

    if (width > req.maxWidth || height > req.maxHeight) {
      warnings.push(`Image larger than recommended. Maximum size: ${req.maxWidth}x${req.maxHeight}px`);
    }

    if (req.square && width !== height) {
      errors.push('Image must be square (equal width and height)');
    }

    if (req.aspectRatio) {
      const ratio = width / height;
      const [minRatio, maxRatio] = req.aspectRatio;
      if (ratio < minRatio || ratio > maxRatio) {
        warnings.push(`Aspect ratio (${ratio.toFixed(2)}) outside recommended range (${minRatio}-${maxRatio})`);
      }
    }

    return { errors, warnings };
  }

  private async validateAssetSecurity(file: File): Promise<{ errors: string[]; warnings: string[] }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check file signature (magic bytes)
    const signature = await this.getFileSignature(file);
    if (!this.isValidImageSignature(signature, file.type)) {
      errors.push('File signature does not match declared type (potential security risk)');
    }

    // Check for embedded scripts in SVG
    if (file.type === 'image/svg+xml') {
      const content = await file.text();
      if (this.containsSVGScripts(content)) {
        errors.push('SVG files with embedded scripts are not allowed');
      }
    }

    // Check file name for suspicious patterns
    if (this.hasSuspiciousFileName(file.name)) {
      warnings.push('File name contains suspicious patterns');
    }

    return { errors, warnings };
  }

  private async getImageMetadata(file: File): Promise<{ width: number; height: number; hasTransparency?: boolean }> {
    return new Promise((resolve, reject) => {
      const img = new Image();
      
      img.onload = () => {
        // Basic metadata
        const metadata = {
          width: img.width,
          height: img.height,
        };

        // Check for transparency (simplified check)
        if (file.type === 'image/png') {
          // PNG can have transparency
          resolve({ ...metadata, hasTransparency: true });
        } else {
          resolve(metadata);
        }
      };

      img.onerror = () => reject(new Error('Failed to load image metadata'));
      img.src = URL.createObjectURL(file);
    });
  }

  private calculateOptimalDimensions(
    originalWidth: number,
    originalHeight: number,
    type: AssetType,
    options: AssetProcessingOptions
  ): { width: number; height: number } {
    let { maxWidth, maxHeight } = options;

    // Set defaults based on asset type
    if (!maxWidth || !maxHeight) {
      const defaults = {
        'logo-primary': { width: 400, height: 120 },
        'logo-secondary': { width: 200, height: 60 },
        'favicon': { width: 256, height: 256 },
        'email-header': { width: 600, height: 150 },
        'report-header': { width: 800, height: 200 },
        'mobile-icon': { width: 256, height: 256 },
        'background': { width: 1920, height: 1080 },
        'watermark': { width: 300, height: 300 },
      };
      
      maxWidth = maxWidth || defaults[type].width;
      maxHeight = maxHeight || defaults[type].height;
    }

    // Calculate aspect ratio preserving dimensions
    const aspectRatio = originalWidth / originalHeight;
    
    let width = Math.min(originalWidth, maxWidth);
    let height = width / aspectRatio;
    
    if (height > maxHeight) {
      height = maxHeight;
      width = height * aspectRatio;
    }

    return {
      width: Math.round(width),
      height: Math.round(height),
    };
  }

  private getOptimalFormat(type: AssetType, originalType: string): AssetFormat {
    // SVG should remain SVG for scalability
    if (originalType === 'image/svg+xml') return 'svg';
    
    // ICO for favicons
    if (type === 'favicon') return 'ico';
    
    // WebP for modern browsers, PNG for transparency, JPG for photos
    if (originalType.includes('png')) return 'png';
    if (originalType.includes('jpg') || originalType.includes('jpeg')) return 'jpg';
    
    return 'png'; // Default fallback
  }

  private async loadImage(file: File): Promise<HTMLImageElement> {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = reject;
      img.src = URL.createObjectURL(file);
    });
  }

  private generateAssetId(): string {
    return `asset_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateVersion(): string {
    return `v${Date.now()}`;
  }

  private generateProcessingId(file: File, tenantId: string): string {
    const content = `${file.name}-${file.size}-${file.lastModified}-${tenantId}`;
    return crypto.createHash('md5').update(content).digest('hex');
  }

  private generateUrlSignature(url: string, expires: number, tenantId: string): string {
    const secret = process.env.ASSET_SIGNING_SECRET || 'default-secret';
    const data = `${url}${expires}${tenantId}`;
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
  }

  private getFileExtension(filename: string): string {
    return filename.split('.').pop()?.toLowerCase() || '';
  }

  private formatFileSize(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${Math.round(bytes / Math.pow(1024, i) * 100) / 100} ${sizes[i]}`;
  }

  private async getFileSignature(file: File): Promise<string> {
    const buffer = await file.slice(0, 4).arrayBuffer();
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private isValidImageSignature(signature: string, mimeType: string): boolean {
    const signatures: Record<string, string[]> = {
      'image/jpeg': ['ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2'],
      'image/png': ['89504e47'],
      'image/gif': ['47494638'],
      'image/webp': ['52494646'],
      'image/svg+xml': ['3c737667', '3c3f786d'], // <svg or <?xml
    };
    
    const validSignatures = signatures[mimeType] || [];
    return validSignatures.some(sig => signature.startsWith(sig));
  }

  private containsSVGScripts(content: string): boolean {
    const scriptPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /javascript:/gi,
    ];
    
    return scriptPatterns.some(pattern => pattern.test(content));
  }

  private hasSuspiciousFileName(filename: string): boolean {
    const suspiciousPatterns = [
      /\.(exe|bat|cmd|scr|pif|com)$/i,
      /[<>:"|?*]/,
      /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(filename));
  }

  // Mock implementations for storage and database operations
  private async uploadToStorage(file: Blob, path: string, tenantId: string): Promise<string> {
    // Mock implementation - would integrate with AWS S3, Google Cloud Storage, etc.
    return `https://cdn.isectech.com/assets/${tenantId}/${path}`;
  }

  private async generateThumbnailUrl(file: Blob, assetId: string, tenantId: string): Promise<string> {
    // Mock implementation
    return `https://cdn.isectech.com/assets/${tenantId}/${assetId}/thumbnail.webp`;
  }

  private async deleteFromStorage(assetId: string, tenantId: string): Promise<void> {
    // Mock implementation
    console.log(`Deleting asset ${assetId} for tenant ${tenantId}`);
  }

  private async fetchAssetFromDatabase(assetId: string, tenantId: string): Promise<BrandAsset | null> {
    // Mock implementation
    return null;
  }

  private async saveAssetToDatabase(asset: BrandAsset): Promise<void> {
    // Mock implementation
    console.log(`Saving asset ${asset.id} to database`);
  }
}

// Export singleton instance
export const assetManager = AssetManager.getInstance();