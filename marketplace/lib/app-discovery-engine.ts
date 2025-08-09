/**
 * App Discovery and Search Engine
 * Production-grade search, discovery, and recommendation system for iSECTECH Marketplace
 */

import Fuse from 'fuse.js';
import type { MarketplaceApp, AppCategory } from '../../developer-portal/lib/app-submission-workflow';

export interface SearchQuery {
  query?: string;
  categories?: AppCategory[];
  tags?: string[];
  securityClassifications?: ('PUBLIC' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET')[];
  priceRange?: {
    min?: number;
    max?: number;
  };
  rating?: {
    min: number;
  };
  popularity?: {
    minDownloads?: number;
    minActiveUsers?: number;
  };
  compatibility?: {
    platformVersions?: string[];
    integrationTypes?: string[];
  };
  sortBy?: 'RELEVANCE' | 'POPULARITY' | 'RATING' | 'RECENT' | 'NAME' | 'PRICE';
  sortOrder?: 'ASC' | 'DESC';
  page?: number;
  pageSize?: number;
}

export interface SearchResult {
  apps: MarketplaceApp[];
  totalCount: number;
  page: number;
  pageSize: number;
  totalPages: number;
  facets: SearchFacets;
  suggestions?: string[];
  relatedQueries?: string[];
}

export interface SearchFacets {
  categories: FacetCount[];
  securityClassifications: FacetCount[];
  priceRanges: FacetCount[];
  ratings: FacetCount[];
  developers: FacetCount[];
  integrationTypes: FacetCount[];
  tags: FacetCount[];
}

export interface FacetCount {
  value: string;
  label: string;
  count: number;
  selected?: boolean;
}

export interface AppRecommendation {
  app: MarketplaceApp;
  reason: 'SIMILAR_CATEGORY' | 'USER_BEHAVIOR' | 'POPULAR' | 'TRENDING' | 'PERSONALIZED';
  score: number;
  explanation: string;
}

export interface RecommendationRequest {
  userId?: string;
  organizationId?: string;
  currentApp?: string;
  userBehavior?: {
    viewedApps: string[];
    installedApps: string[];
    ratedApps: string[];
    searchHistory: string[];
  };
  organizationProfile?: {
    industry: string;
    size: 'SMALL' | 'MEDIUM' | 'LARGE' | 'ENTERPRISE';
    securityRequirements: string[];
    complianceFrameworks: string[];
  };
  contextualFactors?: {
    sessionApps?: string[];
    currentWorkflow?: string;
    timeOfDay?: Date;
    deviceType?: string;
  };
  limit?: number;
}

export class AppDiscoveryEngine {
  private static instance: AppDiscoveryEngine;
  private searchIndex: Fuse<MarketplaceApp>;
  private appCache = new Map<string, MarketplaceApp>();
  private popularityCache = new Map<string, number>();
  private trendingApps: string[] = [];
  private userBehaviorTracker = new Map<string, any>();

  private constructor() {
    this.initializeSearchIndex();
    this.updateTrendingApps();
  }

  public static getInstance(): AppDiscoveryEngine {
    if (!AppDiscoveryEngine.instance) {
      AppDiscoveryEngine.instance = new AppDiscoveryEngine();
    }
    return AppDiscoveryEngine.instance;
  }

  /**
   * Search apps with advanced filtering and faceting
   */
  public async searchApps(query: SearchQuery, userId?: string): Promise<SearchResult> {
    // Track search behavior for recommendations
    if (userId && query.query) {
      this.trackUserBehavior(userId, 'SEARCH', { query: query.query });
    }

    // Get base result set
    let apps = await this.getFilteredApps(query);

    // Apply text search if query provided
    if (query.query?.trim()) {
      const searchResults = this.performTextSearch(apps, query.query);
      apps = searchResults;
    }

    // Apply additional filters
    apps = this.applyFilters(apps, query);

    // Sort results
    apps = this.sortResults(apps, query.sortBy || 'RELEVANCE', query.sortOrder || 'DESC');

    // Calculate facets before pagination
    const facets = this.calculateFacets(apps, query);

    // Apply pagination
    const page = query.page || 1;
    const pageSize = Math.min(query.pageSize || 20, 100);
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedApps = apps.slice(startIndex, endIndex);

    // Generate search suggestions and related queries
    const suggestions = await this.generateSearchSuggestions(query.query);
    const relatedQueries = await this.generateRelatedQueries(query.query, userId);

    return {
      apps: paginatedApps,
      totalCount: apps.length,
      page,
      pageSize,
      totalPages: Math.ceil(apps.length / pageSize),
      facets,
      suggestions,
      relatedQueries,
    };
  }

  /**
   * Get personalized app recommendations
   */
  public async getRecommendations(request: RecommendationRequest): Promise<AppRecommendation[]> {
    const recommendations: AppRecommendation[] = [];
    const limit = request.limit || 10;
    const allApps = Array.from(this.appCache.values()).filter(app => app.status === 'PUBLISHED');

    // Similar category recommendations
    if (request.currentApp) {
      const currentApp = this.appCache.get(request.currentApp);
      if (currentApp) {
        const similarCategoryApps = await this.getSimilarCategoryApps(currentApp, allApps);
        recommendations.push(...similarCategoryApps.slice(0, 3));
      }
    }

    // User behavior-based recommendations
    if (request.userId && request.userBehavior) {
      const behaviorRecommendations = await this.getBehaviorBasedRecommendations(
        request.userId,
        request.userBehavior,
        allApps
      );
      recommendations.push(...behaviorRecommendations.slice(0, 4));
    }

    // Organization profile recommendations
    if (request.organizationProfile) {
      const profileRecommendations = await this.getOrganizationProfileRecommendations(
        request.organizationProfile,
        allApps
      );
      recommendations.push(...profileRecommendations.slice(0, 3));
    }

    // Popular and trending recommendations
    const popularRecommendations = await this.getPopularRecommendations(allApps);
    recommendations.push(...popularRecommendations.slice(0, 2));

    const trendingRecommendations = await this.getTrendingRecommendations(allApps);
    recommendations.push(...trendingRecommendations.slice(0, 2));

    // Remove duplicates and sort by score
    const uniqueRecommendations = this.deduplicateRecommendations(recommendations);
    const sortedRecommendations = uniqueRecommendations
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);

    return sortedRecommendations;
  }

  /**
   * Get featured apps for homepage and category pages
   */
  public async getFeaturedApps(
    category?: AppCategory,
    securityClassification?: string,
    limit: number = 6
  ): Promise<MarketplaceApp[]> {
    const allApps = Array.from(this.appCache.values()).filter(app => 
      app.status === 'PUBLISHED' &&
      (!category || app.category === category) &&
      (!securityClassification || app.securityClassification === securityClassification)
    );

    // Calculate featured score based on multiple factors
    const scoredApps = allApps.map(app => ({
      app,
      score: this.calculateFeaturedScore(app),
    }));

    return scoredApps
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(item => item.app);
  }

  /**
   * Get apps by specific developer
   */
  public async getAppsByDeveloper(developerId: string): Promise<MarketplaceApp[]> {
    return Array.from(this.appCache.values()).filter(
      app => app.developerId === developerId && app.status === 'PUBLISHED'
    );
  }

  /**
   * Get similar apps based on current app
   */
  public async getSimilarApps(appId: string, limit: number = 5): Promise<MarketplaceApp[]> {
    const currentApp = this.appCache.get(appId);
    if (!currentApp) return [];

    const allApps = Array.from(this.appCache.values()).filter(
      app => app.id !== appId && app.status === 'PUBLISHED'
    );

    const similarApps = allApps.map(app => ({
      app,
      similarity: this.calculateAppSimilarity(currentApp, app),
    }));

    return similarApps
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit)
      .map(item => item.app);
  }

  /**
   * Track user behavior for improved recommendations
   */
  public trackUserBehavior(userId: string, action: string, data: any): void {
    if (!this.userBehaviorTracker.has(userId)) {
      this.userBehaviorTracker.set(userId, {
        searches: [],
        views: [],
        installs: [],
        ratings: [],
        lastActivity: new Date(),
      });
    }

    const userBehavior = this.userBehaviorTracker.get(userId);
    
    switch (action) {
      case 'SEARCH':
        userBehavior.searches.push({
          query: data.query,
          timestamp: new Date(),
        });
        break;
      case 'VIEW':
        userBehavior.views.push({
          appId: data.appId,
          timestamp: new Date(),
          duration: data.duration,
        });
        break;
      case 'INSTALL':
        userBehavior.installs.push({
          appId: data.appId,
          timestamp: new Date(),
        });
        break;
      case 'RATE':
        userBehavior.ratings.push({
          appId: data.appId,
          rating: data.rating,
          timestamp: new Date(),
        });
        break;
    }

    userBehavior.lastActivity = new Date();
    
    // Keep only recent behavior (last 90 days)
    const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    Object.keys(userBehavior).forEach(key => {
      if (Array.isArray(userBehavior[key])) {
        userBehavior[key] = userBehavior[key].filter((item: any) => item.timestamp > cutoff);
      }
    });
  }

  /**
   * Update app cache with latest data
   */
  public async updateAppCache(apps: MarketplaceApp[]): Promise<void> {
    this.appCache.clear();
    apps.forEach(app => {
      this.appCache.set(app.id, app);
    });

    // Rebuild search index
    this.initializeSearchIndex();
    
    // Update trending apps
    this.updateTrendingApps();
    
    // Update popularity cache
    this.updatePopularityCache();
  }

  // Private helper methods

  private initializeSearchIndex(): void {
    const apps = Array.from(this.appCache.values());
    const options = {
      keys: [
        { name: 'name', weight: 0.3 },
        { name: 'displayName', weight: 0.3 },
        { name: 'description', weight: 0.2 },
        { name: 'detailedDescription', weight: 0.1 },
        { name: 'category', weight: 0.05 },
        { name: 'subCategory', weight: 0.05 },
      ],
      threshold: 0.4,
      includeScore: true,
      includeMatches: true,
    };

    this.searchIndex = new Fuse(apps, options);
  }

  private async getFilteredApps(query: SearchQuery): Promise<MarketplaceApp[]> {
    return Array.from(this.appCache.values()).filter(app => {
      // Only published apps
      if (app.status !== 'PUBLISHED') return false;

      // Category filter
      if (query.categories?.length && !query.categories.includes(app.category)) return false;

      // Security classification filter
      if (query.securityClassifications?.length && 
          !query.securityClassifications.includes(app.securityClassification)) return false;

      // Price range filter
      if (query.priceRange) {
        const price = this.getAppPrice(app);
        if (query.priceRange.min !== undefined && price < query.priceRange.min) return false;
        if (query.priceRange.max !== undefined && price > query.priceRange.max) return false;
      }

      // Rating filter
      if (query.rating?.min && app.averageRating < query.rating.min) return false;

      // Popularity filter
      if (query.popularity?.minDownloads && app.downloadCount < query.popularity.minDownloads) return false;
      if (query.popularity?.minActiveUsers && app.activeInstallations < query.popularity.minActiveUsers) return false;

      return true;
    });
  }

  private performTextSearch(apps: MarketplaceApp[], searchQuery: string): MarketplaceApp[] {
    if (!searchQuery.trim()) return apps;

    const results = this.searchIndex.search(searchQuery);
    const resultIds = new Set(results.map(result => result.item.id));
    
    return apps.filter(app => resultIds.has(app.id));
  }

  private applyFilters(apps: MarketplaceApp[], query: SearchQuery): MarketplaceApp[] {
    return apps.filter(app => {
      // Tag filters
      if (query.tags?.length) {
        // Assuming apps have tags - in real implementation would be in app metadata
        const appTags = this.getAppTags(app);
        const hasMatchingTag = query.tags.some(tag => appTags.includes(tag));
        if (!hasMatchingTag) return false;
      }

      // Compatibility filters
      if (query.compatibility?.platformVersions?.length) {
        const supportedVersions = this.getSupportedPlatformVersions(app);
        const hasCompatibleVersion = query.compatibility.platformVersions.some(
          version => supportedVersions.includes(version)
        );
        if (!hasCompatibleVersion) return false;
      }

      return true;
    });
  }

  private sortResults(
    apps: MarketplaceApp[], 
    sortBy: SearchQuery['sortBy'], 
    sortOrder: SearchQuery['sortOrder']
  ): MarketplaceApp[] {
    const sorted = [...apps].sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'RELEVANCE':
          // Relevance score based on multiple factors
          comparison = this.calculateRelevanceScore(b) - this.calculateRelevanceScore(a);
          break;
        case 'POPULARITY':
          comparison = b.downloadCount - a.downloadCount;
          break;
        case 'RATING':
          comparison = b.averageRating - a.averageRating;
          break;
        case 'RECENT':
          comparison = b.publishedAt!.getTime() - a.publishedAt!.getTime();
          break;
        case 'NAME':
          comparison = a.displayName.localeCompare(b.displayName);
          break;
        case 'PRICE':
          comparison = this.getAppPrice(a) - this.getAppPrice(b);
          break;
        default:
          comparison = 0;
      }
      
      return sortOrder === 'ASC' ? -comparison : comparison;
    });

    return sorted;
  }

  private calculateFacets(apps: MarketplaceApp[], query: SearchQuery): SearchFacets {
    // Calculate category facets
    const categoryMap = new Map<string, number>();
    const classificationMap = new Map<string, number>();
    const priceMap = new Map<string, number>();
    const ratingMap = new Map<string, number>();
    const developerMap = new Map<string, number>();

    apps.forEach(app => {
      // Categories
      categoryMap.set(app.category, (categoryMap.get(app.category) || 0) + 1);
      
      // Security classifications
      classificationMap.set(app.securityClassification, (classificationMap.get(app.securityClassification) || 0) + 1);
      
      // Price ranges
      const price = this.getAppPrice(app);
      const priceRange = this.getPriceRange(price);
      priceMap.set(priceRange, (priceMap.get(priceRange) || 0) + 1);
      
      // Rating ranges
      const ratingRange = this.getRatingRange(app.averageRating);
      ratingMap.set(ratingRange, (ratingMap.get(ratingRange) || 0) + 1);
      
      // Developers (would get developer name from lookup)
      const developerName = `Developer ${app.developerId.slice(-4)}`;
      developerMap.set(developerName, (developerMap.get(developerName) || 0) + 1);
    });

    return {
      categories: this.mapToFacetCounts(categoryMap, 'CATEGORY'),
      securityClassifications: this.mapToFacetCounts(classificationMap, 'CLASSIFICATION'),
      priceRanges: this.mapToFacetCounts(priceMap, 'PRICE'),
      ratings: this.mapToFacetCounts(ratingMap, 'RATING'),
      developers: this.mapToFacetCounts(developerMap, 'DEVELOPER'),
      integrationTypes: [], // Would be calculated from app integration points
      tags: [], // Would be calculated from app tags
    };
  }

  private calculateRelevanceScore(app: MarketplaceApp): number {
    let score = 0;
    
    // Base score from rating
    score += app.averageRating * 10;
    
    // Popularity boost
    score += Math.log(app.downloadCount + 1) * 2;
    
    // Recent activity boost
    const daysSinceUpdate = (Date.now() - app.updatedAt.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceUpdate < 30) score += 20;
    else if (daysSinceUpdate < 90) score += 10;
    
    // Security review score
    score += app.securityReview.overallScore * 0.5;
    
    // Trending boost
    if (this.trendingApps.includes(app.id)) score += 25;
    
    return score;
  }

  private calculateFeaturedScore(app: MarketplaceApp): number {
    let score = 0;
    
    // High rating requirement for featured apps
    score += app.averageRating * 15;
    
    // Download count impact
    score += Math.log(app.downloadCount + 1) * 3;
    
    // Active installations
    score += Math.log(app.activeInstallations + 1) * 2;
    
    // Security score requirement
    score += app.securityReview.overallScore * 0.8;
    
    // Recent updates boost
    const daysSinceUpdate = (Date.now() - app.updatedAt.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceUpdate < 30) score += 30;
    
    // Developer reputation (mock)
    score += 20;
    
    return score;
  }

  private calculateAppSimilarity(app1: MarketplaceApp, app2: MarketplaceApp): number {
    let similarity = 0;
    
    // Same category
    if (app1.category === app2.category) similarity += 40;
    
    // Similar security classification
    if (app1.securityClassification === app2.securityClassification) similarity += 20;
    
    // Similar architecture type
    if (app1.architecture.type === app2.architecture.type) similarity += 15;
    
    // Similar pricing model
    if (app1.pricing.model === app2.pricing.model) similarity += 10;
    
    // Similar rating range
    const ratingDiff = Math.abs(app1.averageRating - app2.averageRating);
    similarity += Math.max(0, 15 - ratingDiff * 3);
    
    return similarity;
  }

  // Recommendation helper methods
  private async getSimilarCategoryApps(currentApp: MarketplaceApp, allApps: MarketplaceApp[]): Promise<AppRecommendation[]> {
    return allApps
      .filter(app => app.category === currentApp.category && app.id !== currentApp.id)
      .sort((a, b) => b.averageRating - a.averageRating)
      .slice(0, 3)
      .map(app => ({
        app,
        reason: 'SIMILAR_CATEGORY' as const,
        score: 70 + app.averageRating * 5,
        explanation: `Similar to ${currentApp.displayName} in ${currentApp.category}`,
      }));
  }

  private async getBehaviorBasedRecommendations(
    userId: string,
    behavior: any,
    allApps: MarketplaceApp[]
  ): Promise<AppRecommendation[]> {
    const userBehavior = this.userBehaviorTracker.get(userId);
    if (!userBehavior) return [];

    // Find apps similar to ones user has viewed/installed
    const viewedAppIds = behavior.viewedApps || [];
    const installedAppIds = behavior.installedApps || [];
    
    const interestingApps = new Set([...viewedAppIds, ...installedAppIds]);
    
    const recommendations: AppRecommendation[] = [];
    
    for (const appId of interestingApps) {
      const app = this.appCache.get(appId);
      if (app) {
        const similarApps = await this.getSimilarApps(appId, 2);
        similarApps.forEach(similarApp => {
          recommendations.push({
            app: similarApp,
            reason: 'USER_BEHAVIOR',
            score: 60 + similarApp.averageRating * 3,
            explanation: `Based on your interest in ${app.displayName}`,
          });
        });
      }
    }
    
    return recommendations;
  }

  private async getOrganizationProfileRecommendations(
    profile: any,
    allApps: MarketplaceApp[]
  ): Promise<AppRecommendation[]> {
    // Filter apps relevant to organization industry and size
    const relevantApps = allApps.filter(app => {
      // Industry-specific apps
      if (profile.industry === 'FINANCIAL' && app.category === 'COMPLIANCE_TEMPLATES') return true;
      if (profile.industry === 'HEALTHCARE' && app.securityClassification !== 'PUBLIC') return true;
      
      // Size-appropriate apps
      if (profile.size === 'ENTERPRISE' && app.pricing.model === 'USAGE_BASED') return true;
      if (profile.size === 'SMALL' && app.pricing.model === 'FREE') return true;
      
      return false;
    });

    return relevantApps
      .slice(0, 3)
      .map(app => ({
        app,
        reason: 'PERSONALIZED' as const,
        score: 55 + app.averageRating * 4,
        explanation: `Recommended for ${profile.industry} organizations`,
      }));
  }

  private async getPopularRecommendations(allApps: MarketplaceApp[]): Promise<AppRecommendation[]> {
    return allApps
      .sort((a, b) => b.downloadCount - a.downloadCount)
      .slice(0, 2)
      .map(app => ({
        app,
        reason: 'POPULAR' as const,
        score: 45 + Math.log(app.downloadCount + 1) * 2,
        explanation: `Popular with ${app.downloadCount.toLocaleString()} downloads`,
      }));
  }

  private async getTrendingRecommendations(allApps: MarketplaceApp[]): Promise<AppRecommendation[]> {
    return allApps
      .filter(app => this.trendingApps.includes(app.id))
      .slice(0, 2)
      .map(app => ({
        app,
        reason: 'TRENDING' as const,
        score: 50 + app.averageRating * 3,
        explanation: 'Trending in the security community',
      }));
  }

  private deduplicateRecommendations(recommendations: AppRecommendation[]): AppRecommendation[] {
    const seen = new Set<string>();
    return recommendations.filter(rec => {
      if (seen.has(rec.app.id)) return false;
      seen.add(rec.app.id);
      return true;
    });
  }

  // Utility methods
  private getAppPrice(app: MarketplaceApp): number {
    return app.pricing.basePrice || 0;
  }

  private getPriceRange(price: number): string {
    if (price === 0) return 'Free';
    if (price < 10) return '$0-$10';
    if (price < 50) return '$10-$50';
    if (price < 100) return '$50-$100';
    return '$100+';
  }

  private getRatingRange(rating: number): string {
    if (rating >= 4.5) return '4.5+ stars';
    if (rating >= 4.0) return '4.0+ stars';
    if (rating >= 3.5) return '3.5+ stars';
    if (rating >= 3.0) return '3.0+ stars';
    return 'Under 3.0 stars';
  }

  private mapToFacetCounts(map: Map<string, number>, type: string): FacetCount[] {
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({
        value,
        label: this.formatFacetLabel(value, type),
        count,
      }));
  }

  private formatFacetLabel(value: string, type: string): string {
    switch (type) {
      case 'CATEGORY':
        return value.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      case 'CLASSIFICATION':
        return value.charAt(0) + value.slice(1).toLowerCase();
      default:
        return value;
    }
  }

  private getAppTags(app: MarketplaceApp): string[] {
    // Mock implementation - in real app, would extract from app metadata
    return [app.category.toLowerCase(), app.subCategory?.toLowerCase() || ''].filter(Boolean);
  }

  private getSupportedPlatformVersions(app: MarketplaceApp): string[] {
    // Mock implementation - would be from app system requirements
    return ['2.0.0', '2.1.0', '2.2.0'];
  }

  private async generateSearchSuggestions(query?: string): Promise<string[]> {
    if (!query) return [];
    
    // Mock suggestions - in production would use ML model or search analytics
    const baseSuggestions = [
      'threat intelligence',
      'vulnerability scanner',
      'security dashboard',
      'compliance reporting',
      'incident response',
      'asset management',
    ];
    
    return baseSuggestions.filter(suggestion => 
      suggestion.toLowerCase().includes(query.toLowerCase()) ||
      query.toLowerCase().includes(suggestion.toLowerCase())
    );
  }

  private async generateRelatedQueries(query?: string, userId?: string): Promise<string[]> {
    // Mock related queries - in production would use user behavior analytics
    return [
      'security monitoring tools',
      'threat detection apps',
      'compliance automation',
      'vulnerability assessment',
    ];
  }

  private updateTrendingApps(): void {
    // Mock trending calculation - in production would analyze recent download/usage patterns
    const apps = Array.from(this.appCache.values());
    this.trendingApps = apps
      .filter(app => app.status === 'PUBLISHED')
      .sort((a, b) => {
        const aScore = this.calculateTrendingScore(a);
        const bScore = this.calculateTrendingScore(b);
        return bScore - aScore;
      })
      .slice(0, 10)
      .map(app => app.id);
  }

  private calculateTrendingScore(app: MarketplaceApp): number {
    const daysSincePublish = (Date.now() - (app.publishedAt?.getTime() || 0)) / (1000 * 60 * 60 * 24);
    const recentnessBoost = Math.max(0, 30 - daysSincePublish) * 2;
    
    return app.downloadCount * 0.1 + app.averageRating * 10 + recentnessBoost;
  }

  private updatePopularityCache(): void {
    const apps = Array.from(this.appCache.values());
    apps.forEach(app => {
      const popularity = app.downloadCount * 0.6 + app.activeInstallations * 0.4;
      this.popularityCache.set(app.id, popularity);
    });
  }
}

// Export singleton instance
export const appDiscoveryEngine = AppDiscoveryEngine.getInstance();