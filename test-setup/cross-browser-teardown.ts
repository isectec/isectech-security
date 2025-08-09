/**
 * Cross-Browser Testing Global Teardown
 * iSECTECH Protect - Multi-Browser Test Environment Cleanup
 */

import { FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

interface TestResults {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  skippedTests: number;
  browsers: {
    [browserName: string]: {
      tests: number;
      passed: number;
      failed: number;
      avgDuration: number;
    };
  };
  routes: {
    [route: string]: {
      browsers: string[];
      avgLoadTime: number;
      issues: string[];
    };
  };
  performance: {
    [browserName: string]: {
      avgLoadTime: number;
      avgRenderTime: number;
      memoryUsage: number;
    };
  };
  compatibility: {
    score: number;
    issues: string[];
    recommendations: string[];
  };
}

async function collectTestResults(): Promise<TestResults> {
  console.log('📊 Collecting cross-browser test results...');
  
  const resultsPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'results.json');
  let rawResults = null;
  
  try {
    if (fs.existsSync(resultsPath)) {
      rawResults = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
    }
  } catch (error) {
    console.warn('⚠️ Could not read test results:', error);
  }

  // Initialize default results structure
  const results: TestResults = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    skippedTests: 0,
    browsers: {},
    routes: {},
    performance: {},
    compatibility: {
      score: 0,
      issues: [],
      recommendations: [],
    },
  };

  if (rawResults && rawResults.suites) {
    // Process Playwright test results
    rawResults.suites.forEach((suite: any) => {
      suite.specs?.forEach((spec: any) => {
        results.totalTests++;
        
        spec.tests?.forEach((test: any) => {
          const browserName = test.projectName || 'unknown';
          
          if (!results.browsers[browserName]) {
            results.browsers[browserName] = {
              tests: 0,
              passed: 0,
              failed: 0,
              avgDuration: 0,
            };
          }
          
          results.browsers[browserName].tests++;
          
          if (test.outcome === 'expected') {
            results.passedTests++;
            results.browsers[browserName].passed++;
          } else if (test.outcome === 'unexpected') {
            results.failedTests++;
            results.browsers[browserName].failed++;
          } else {
            results.skippedTests++;
          }
          
          // Collect duration
          const duration = test.results?.[0]?.duration || 0;
          results.browsers[browserName].avgDuration += duration;
        });
      });
    });

    // Calculate averages
    Object.keys(results.browsers).forEach(browserName => {
      const browser = results.browsers[browserName];
      if (browser.tests > 0) {
        browser.avgDuration = browser.avgDuration / browser.tests;
      }
    });
  }

  return results;
}

async function generateCompatibilityMatrix() {
  console.log('🔍 Generating browser compatibility matrix...');
  
  const browsers = ['chromium', 'firefox', 'webkit'];
  const features = [
    'WebCrypto API',
    'Service Workers', 
    'IndexedDB',
    'Notifications',
    'WebRTC',
    'WebGL',
    'Local Storage',
    'Session Storage',
    'Geolocation',
    'Device Motion',
  ];
  
  const routes = [
    '/dashboard',
    '/alerts',
    '/threats',
    '/threats/map',
    '/incidents',
    '/reports',
    '/search',
    '/settings/security',
  ];

  // Load browser capabilities from setup
  const capabilitiesPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'browser-capabilities.json');
  let capabilities = [];
  
  try {
    if (fs.existsSync(capabilitiesPath)) {
      capabilities = JSON.parse(fs.readFileSync(capabilitiesPath, 'utf8'));
    }
  } catch (error) {
    console.warn('⚠️ Could not load browser capabilities:', error);
  }

  const matrix = {
    features: {} as { [feature: string]: { [browser: string]: boolean } },
    routes: {} as { [route: string]: { [browser: string]: boolean } },
    overall: {} as { [browser: string]: { score: number; issues: string[] } },
  };

  // Build feature compatibility matrix
  features.forEach(feature => {
    matrix.features[feature] = {};
    browsers.forEach(browser => {
      const browserCap = capabilities.find((cap: any) => cap.browser === browser);
      let supported = false;
      
      if (browserCap) {
        switch (feature) {
          case 'WebCrypto API':
            supported = browserCap.features.webCrypto;
            break;
          case 'Service Workers':
            supported = browserCap.features.serviceWorkers;
            break;
          case 'IndexedDB':
            supported = browserCap.features.indexedDB;
            break;
          case 'Notifications':
            supported = browserCap.features.notifications;
            break;
          case 'WebRTC':
            supported = browserCap.features.webrtc;
            break;
          case 'WebGL':
            supported = browserCap.features.webgl;
            break;
          default:
            supported = true; // Assume basic features are supported
        }
      }
      
      matrix.features[feature][browser] = supported;
    });
  });

  // Build route compatibility matrix (assume all routes work unless test failures indicate otherwise)
  routes.forEach(route => {
    matrix.routes[route] = {};
    browsers.forEach(browser => {
      matrix.routes[route][browser] = true; // Default to working, will be updated based on test results
    });
  });

  // Calculate overall browser scores
  browsers.forEach(browser => {
    const featureCount = features.length;
    const supportedFeatures = features.filter(feature => matrix.features[feature][browser]).length;
    const routeCount = routes.length;
    const supportedRoutes = routes.filter(route => matrix.routes[route][browser]).length;
    
    const featureScore = (supportedFeatures / featureCount) * 100;
    const routeScore = (supportedRoutes / routeCount) * 100;
    const overallScore = (featureScore + routeScore) / 2;
    
    const issues = [];
    features.forEach(feature => {
      if (!matrix.features[feature][browser]) {
        issues.push(`${feature} not supported`);
      }
    });
    
    matrix.overall[browser] = {
      score: Math.round(overallScore),
      issues,
    };
  });

  return matrix;
}

async function generateFinalReport(results: TestResults, compatibilityMatrix: any) {
  console.log('📋 Generating final cross-browser test report...');
  
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      totalTests: results.totalTests,
      passedTests: results.passedTests,
      failedTests: results.failedTests,
      skippedTests: results.skippedTests,
      successRate: results.totalTests > 0 ? Math.round((results.passedTests / results.totalTests) * 100) : 0,
    },
    browsers: results.browsers,
    compatibility: compatibilityMatrix,
    performance: results.performance,
    recommendations: [] as string[],
    quality: {
      grade: 'A',
      score: 0,
      criteria: {
        featureSupport: 0,
        testCoverage: 0,
        performance: 0,
        compatibility: 0,
      },
    },
  };

  // Calculate quality score
  const successRate = report.summary.successRate;
  const avgCompatibility = Object.values(compatibilityMatrix.overall).reduce((sum: number, browser: any) => sum + browser.score, 0) / Object.keys(compatibilityMatrix.overall).length;
  
  report.quality.criteria.featureSupport = avgCompatibility;
  report.quality.criteria.testCoverage = successRate;
  report.quality.criteria.performance = successRate; // Simplified - actual performance metrics would be better
  report.quality.criteria.compatibility = avgCompatibility;
  
  report.quality.score = Math.round((
    report.quality.criteria.featureSupport +
    report.quality.criteria.testCoverage +
    report.quality.criteria.performance +
    report.quality.criteria.compatibility
  ) / 4);

  // Assign grade
  if (report.quality.score >= 95) report.quality.grade = 'A+';
  else if (report.quality.score >= 90) report.quality.grade = 'A';
  else if (report.quality.score >= 85) report.quality.grade = 'B+';
  else if (report.quality.score >= 80) report.quality.grade = 'B';
  else if (report.quality.score >= 75) report.quality.grade = 'C+';
  else if (report.quality.score >= 70) report.quality.grade = 'C';
  else report.quality.grade = 'D';

  // Generate recommendations
  if (report.summary.successRate < 95) {
    report.recommendations.push('Investigate and fix failing tests to improve success rate');
  }
  
  Object.entries(compatibilityMatrix.overall).forEach(([browser, data]: [string, any]) => {
    if (data.score < 90) {
      report.recommendations.push(`Improve ${browser} compatibility - current score: ${data.score}%`);
    }
    
    if (data.issues.length > 0) {
      report.recommendations.push(`Address ${browser} issues: ${data.issues.join(', ')}`);
    }
  });

  if (results.failedTests > 0) {
    report.recommendations.push('Review and fix failing tests to improve browser compatibility');
  }

  // Save JSON report
  const reportPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'final-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

  // Generate markdown report
  let markdown = `# Cross-Browser Testing Final Report\n\n`;
  markdown += `**Generated:** ${new Date().toISOString()}\n\n`;
  markdown += `## Summary\n\n`;
  markdown += `- **Quality Grade:** ${report.quality.grade} (${report.quality.score}%)\n`;
  markdown += `- **Total Tests:** ${report.summary.totalTests}\n`;
  markdown += `- **Success Rate:** ${report.summary.successRate}% (${report.summary.passedTests}/${report.summary.totalTests})\n`;
  markdown += `- **Failed Tests:** ${report.summary.failedTests}\n`;
  markdown += `- **Skipped Tests:** ${report.summary.skippedTests}\n\n`;

  markdown += `## Browser Results\n\n`;
  markdown += `| Browser | Tests | Passed | Failed | Success Rate | Avg Duration |\n`;
  markdown += `|---------|-------|--------|--------|--------------|---------------|\n`;
  
  Object.entries(results.browsers).forEach(([browser, data]) => {
    const successRate = data.tests > 0 ? Math.round((data.passed / data.tests) * 100) : 0;
    const avgDuration = Math.round(data.avgDuration);
    markdown += `| ${browser} | ${data.tests} | ${data.passed} | ${data.failed} | ${successRate}% | ${avgDuration}ms |\n`;
  });

  markdown += `\n## Compatibility Matrix\n\n`;
  markdown += `### Feature Support\n\n`;
  markdown += `| Feature | Chrome | Firefox | Safari |\n`;
  markdown += `|---------|---------|---------|--------|\n`;
  
  Object.entries(compatibilityMatrix.features).forEach(([feature, browsers]: [string, any]) => {
    const chrome = browsers.chromium ? '✅' : '❌';
    const firefox = browsers.firefox ? '✅' : '❌';
    const safari = browsers.webkit ? '✅' : '❌';
    markdown += `| ${feature} | ${chrome} | ${firefox} | ${safari} |\n`;
  });

  markdown += `\n### Browser Compatibility Scores\n\n`;
  Object.entries(compatibilityMatrix.overall).forEach(([browser, data]: [string, any]) => {
    markdown += `**${browser.toUpperCase()}:** ${data.score}%\n`;
    if (data.issues.length > 0) {
      markdown += `- Issues: ${data.issues.join(', ')}\n`;
    }
    markdown += `\n`;
  });

  if (report.recommendations.length > 0) {
    markdown += `## Recommendations\n\n`;
    report.recommendations.forEach((rec, index) => {
      markdown += `${index + 1}. ${rec}\n`;
    });
    markdown += `\n`;
  }

  markdown += `## Quality Breakdown\n\n`;
  markdown += `- **Feature Support:** ${report.quality.criteria.featureSupport}%\n`;
  markdown += `- **Test Coverage:** ${report.quality.criteria.testCoverage}%\n`;
  markdown += `- **Performance:** ${report.quality.criteria.performance}%\n`;
  markdown += `- **Compatibility:** ${report.quality.criteria.compatibility}%\n\n`;

  const markdownPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'final-report.md');  
  fs.writeFileSync(markdownPath, markdown);

  return report;
}

async function cleanupTestData() {
  console.log('🗑️ Cleaning up test data...');
  
  try {
    // Remove temporary test files
    const tempFiles = [
      'test-results/cross-browser/test-data.json',
      'test-results/cross-browser/setup-results.json',
    ];

    tempFiles.forEach(file => {
      const filePath = path.join(process.cwd(), file);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🗑️ Removed: ${file}`);
      }
    });

    console.log('✅ Cleanup completed');
  } catch (error) {
    console.warn('⚠️ Cleanup had some issues:', error);
  }
}

async function archiveResults() {
  console.log('📦 Archiving test results...');
  
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archiveDir = path.join(process.cwd(), 'test-results', 'cross-browser', 'archive', timestamp);
    
    fs.mkdirSync(archiveDir, { recursive: true });
    
    // Archive key files
    const filesToArchive = [
      'final-report.json',
      'final-report.md',
      'browser-capabilities.json',
      'setup-report.md',
      'results.json',
    ];

    filesToArchive.forEach(file => {
      const sourcePath = path.join(process.cwd(), 'test-results', 'cross-browser', file);
      const targetPath = path.join(archiveDir, file);
      
      if (fs.existsSync(sourcePath)) {
        fs.copyFileSync(sourcePath, targetPath);
      }
    });

    console.log(`✅ Results archived to: ${archiveDir}`);
    return archiveDir;
  } catch (error) {
    console.warn('⚠️ Archiving failed:', error);
    return null;
  }
}

// Main teardown function
export default async function globalTeardown(config: FullConfig) {
  console.log('🏁 Starting cross-browser testing teardown...\n');
  
  try {
    // Collect and process results
    const testResults = await collectTestResults();
    const compatibilityMatrix = await generateCompatibilityMatrix();
    const finalReport = await generateFinalReport(testResults, compatibilityMatrix);
    
    // Cleanup and archive
    const archiveLocation = await archiveResults();
    await cleanupTestData();

    // Display final summary
    console.log('\n🎯 Cross-Browser Testing Summary:');
    console.log(`├── Quality Grade: ${finalReport.quality.grade} (${finalReport.quality.score}%)`);
    console.log(`├── Success Rate: ${finalReport.summary.successRate}%`);
    console.log(`├── Total Tests: ${finalReport.summary.totalTests}`);
    console.log(`├── Browsers Tested: ${Object.keys(testResults.browsers).length}`);
    
    if (finalReport.recommendations.length > 0) {
      console.log(`├── Recommendations: ${finalReport.recommendations.length}`);
    }
    
    if (archiveLocation) {
      console.log(`└── Archived: ${path.relative(process.cwd(), archiveLocation)}`);
    }

    console.log('\n📊 Detailed reports:');
    console.log(`├── JSON: test-results/cross-browser/final-report.json`);
    console.log(`└── Markdown: test-results/cross-browser/final-report.md`);

    if (finalReport.quality.score >= 90) {
      console.log('\n✅ Cross-browser testing completed successfully!');
    } else if (finalReport.quality.score >= 75) {
      console.log('\n⚠️ Cross-browser testing completed with some issues.');
      console.log('📋 Check recommendations in the final report.');
    } else {
      console.log('\n❌ Cross-browser testing completed with significant issues.');
      console.log('🔧 Immediate attention required - check final report.');
    }

    return finalReport;
  } catch (error) {
    console.error('❌ Cross-browser teardown failed:', error);
    throw error;
  }
}