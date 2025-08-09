/**
 * Lighthouse Performance Testing Script
 * Production-grade performance testing for iSECTECH Protect
 */

const lighthouse = require('lighthouse');
const chromeLauncher = require('chrome-launcher');
const fs = require('fs').promises;
const path = require('path');

// Performance budgets for security application
const PERFORMANCE_BUDGETS = {
  // Time-based metrics (milliseconds)
  'first-contentful-paint': 2000,
  'largest-contentful-paint': 4000,
  'first-meaningful-paint': 2500,
  'speed-index': 3000,
  interactive: 5000,
  'total-blocking-time': 300,
  'cumulative-layout-shift': 0.1,

  // Size-based metrics (bytes)
  'total-byte-weight': 1000000, // 1MB
  'dom-size': 1000,
  'script-treemap-data': 500000, // 500KB JS
  'render-blocking-resources': 100000, // 100KB CSS
};

// Security-specific audits
const SECURITY_AUDITS = [
  'is-on-https',
  'uses-http2',
  'no-vulnerable-libraries',
  'csp-xss',
  'external-anchors-use-rel-noopener',
  'geolocation-on-start',
  'notification-on-start',
  'password-inputs-can-be-pasted-into',
];

async function runLighthouse(url, options = {}) {
  console.log(`🔍 Running Lighthouse audit for: ${url}`);

  const chrome = await chromeLauncher.launch({
    chromeFlags: ['--headless', '--no-sandbox', '--disable-gpu'],
  });

  const config = {
    extends: 'lighthouse:default',
    settings: {
      // Security-focused configuration
      onlyAudits: [
        // Performance
        'first-contentful-paint',
        'largest-contentful-paint',
        'first-meaningful-paint',
        'speed-index',
        'interactive',
        'total-blocking-time',
        'cumulative-layout-shift',
        'total-byte-weight',
        'dom-size',
        'render-blocking-resources',

        // Security
        ...SECURITY_AUDITS,

        // Accessibility
        'accessibility',
        'color-contrast',
        'aria-valid-attr',
        'aria-required-attr',
        'keyboard-navigation',

        // Best practices
        'uses-https',
        'is-crawlable',
        'meta-description',
        'document-title',
      ],

      // Mobile-first testing for security professionals on the go
      formFactor: options.mobile ? 'mobile' : 'desktop',
      screenEmulation: options.mobile
        ? {
            mobile: true,
            width: 360,
            height: 640,
            deviceScaleFactor: 2,
          }
        : {
            mobile: false,
            width: 1350,
            height: 940,
            deviceScaleFactor: 1,
          },

      // Throttling for realistic conditions
      throttling: options.throttling || {
        rttMs: 40,
        throughputKbps: 10240,
        cpuSlowdownMultiplier: 1,
      },
    },
  };

  try {
    const runnerResult = await lighthouse(
      url,
      {
        port: chrome.port,
        output: ['json', 'html'],
        logLevel: 'error',
      },
      config
    );

    await chrome.kill();

    return runnerResult;
  } catch (error) {
    await chrome.kill();
    throw error;
  }
}

function analyzeResults(lhr) {
  const results = {
    score: Math.round(lhr.score * 100),
    metrics: {},
    security: {},
    accessibility: {},
    budgetViolations: [],
    recommendations: [],
  };

  // Analyze performance metrics
  Object.entries(PERFORMANCE_BUDGETS).forEach(([audit, budget]) => {
    const auditResult = lhr.audits[audit];
    if (auditResult) {
      const value = auditResult.numericValue || auditResult.score;
      results.metrics[audit] = {
        value,
        budget,
        passed: value <= budget,
        score: auditResult.score,
      };

      if (value > budget) {
        results.budgetViolations.push({
          audit,
          value,
          budget,
          overage: value - budget,
        });
      }
    }
  });

  // Analyze security audits
  SECURITY_AUDITS.forEach((audit) => {
    const auditResult = lhr.audits[audit];
    if (auditResult) {
      results.security[audit] = {
        passed: auditResult.score === 1,
        score: auditResult.score,
        title: auditResult.title,
        description: auditResult.description,
      };

      if (auditResult.score < 1) {
        results.recommendations.push({
          type: 'security',
          audit,
          title: auditResult.title,
          description: auditResult.description,
          details: auditResult.details,
        });
      }
    }
  });

  // Analyze accessibility
  const a11yAudits = ['color-contrast', 'aria-valid-attr', 'aria-required-attr'];
  a11yAudits.forEach((audit) => {
    const auditResult = lhr.audits[audit];
    if (auditResult) {
      results.accessibility[audit] = {
        passed: auditResult.score === 1,
        score: auditResult.score,
        title: auditResult.title,
      };
    }
  });

  return results;
}

function generateReport(results, url) {
  console.log('\n📊 Lighthouse Performance Report');
  console.log('================================');
  console.log(`URL: ${url}`);
  console.log(`Overall Score: ${results.score}/100`);

  console.log('\n⚡ Performance Metrics:');
  Object.entries(results.metrics).forEach(([metric, data]) => {
    const status = data.passed ? '✅' : '❌';
    const value =
      typeof data.value === 'number'
        ? data.value > 1000
          ? `${(data.value / 1000).toFixed(1)}s`
          : `${Math.round(data.value)}ms`
        : data.value;
    console.log(`  ${status} ${metric}: ${value} (budget: ${data.budget})`);
  });

  if (results.budgetViolations.length > 0) {
    console.log('\n🚨 Budget Violations:');
    results.budgetViolations.forEach((violation) => {
      console.log(`  ❌ ${violation.audit}: ${violation.overage} over budget`);
    });
  }

  console.log('\n🔒 Security Audits:');
  Object.entries(results.security).forEach(([audit, data]) => {
    const status = data.passed ? '✅' : '❌';
    console.log(`  ${status} ${data.title}`);
  });

  console.log('\n♿ Accessibility:');
  Object.entries(results.accessibility).forEach(([audit, data]) => {
    const status = data.passed ? '✅' : '❌';
    console.log(`  ${status} ${data.title}`);
  });

  if (results.recommendations.length > 0) {
    console.log('\n💡 Recommendations:');
    results.recommendations.forEach((rec) => {
      console.log(`  • ${rec.title}: ${rec.description}`);
    });
  }

  return results.score >= 80 && results.budgetViolations.length === 0;
}

async function main() {
  const baseUrl = process.env.LIGHTHOUSE_URL || 'http://localhost:3000';
  const outputDir = path.join(process.cwd(), 'test-results');

  // Ensure output directory exists
  await fs.mkdir(outputDir, { recursive: true });

  const pages = [
    { path: '/', name: 'homepage' },
    { path: '/dashboard', name: 'dashboard' },
    { path: '/alerts', name: 'alerts' },
    { path: '/threats', name: 'threats' },
  ];

  let allPassed = true;

  for (const page of pages) {
    const url = `${baseUrl}${page.path}`;

    try {
      console.log(`\n🔍 Testing ${page.name} (${url})`);

      // Test desktop
      const desktopResult = await runLighthouse(url, { mobile: false });
      const desktopAnalysis = analyzeResults(desktopResult.lhr);

      // Test mobile
      const mobileResult = await runLighthouse(url, { mobile: true });
      const mobileAnalysis = analyzeResults(mobileResult.lhr);

      // Generate reports
      console.log('\n📱 Desktop Results:');
      const desktopPassed = generateReport(desktopAnalysis, url);

      console.log('\n📱 Mobile Results:');
      const mobilePassed = generateReport(mobileAnalysis, url);

      // Save detailed reports
      await fs.writeFile(
        path.join(outputDir, `lighthouse-${page.name}-desktop.json`),
        JSON.stringify(desktopResult.lhr, null, 2)
      );

      await fs.writeFile(
        path.join(outputDir, `lighthouse-${page.name}-mobile.json`),
        JSON.stringify(mobileResult.lhr, null, 2)
      );

      if (desktopResult.report) {
        await fs.writeFile(path.join(outputDir, `lighthouse-${page.name}-desktop.html`), desktopResult.report);
      }

      if (mobileResult.report) {
        await fs.writeFile(path.join(outputDir, `lighthouse-${page.name}-mobile.html`), mobileResult.report);
      }

      if (!desktopPassed || !mobilePassed) {
        allPassed = false;
      }
    } catch (error) {
      console.error(`❌ Error testing ${page.name}:`, error.message);
      allPassed = false;
    }
  }

  if (allPassed) {
    console.log('\n✅ All Lighthouse tests passed!');
    process.exit(0);
  } else {
    console.log('\n❌ Some Lighthouse tests failed. Check the reports for details.');
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error('❌ Lighthouse testing failed:', error);
    process.exit(1);
  });
}
