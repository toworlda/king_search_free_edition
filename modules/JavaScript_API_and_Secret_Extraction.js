/**
 * Advanced JavaScript Analysis & API Extraction Tool
 * Enhanced for Bug Bounty and Pentesting
 * 
 * This script analyzes JavaScript files to detect hidden API endpoints,
 * secrets, tokens, and security vulnerabilities.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Create directory if it doesn't exist
const ensureDirectoryExists = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`Created directory: ${dirPath}`);
  }
};

// Base directory for the script
const baseDir = path.resolve(process.env.HOME, 'king_search/modules');
// Results directory
const resultsDir = path.join(process.env.HOME, 'king_search/Reports/js-scanner');

// Ensure directories exist
ensureDirectoryExists(baseDir);
ensureDirectoryExists(resultsDir);

// Regex patterns to identify potential sensitive information and vulnerabilities
const PATTERNS = {
  // API endpoints
  apiEndpoints: [
    /['"`]https?:\/\/[^'"`\s]+\/api\/[^'"`\s]+['"`]/gi,
    /['"`]https?:\/\/[^'"`\s]+\/v[0-9]+\/[^'"`\s]+['"`]/gi,
    /['"`]\/api\/[^'"`\s]+['"`]/gi,
    /\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]/gi,
    /axios\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]/gi,
    /fetch\s*\(\s*['"`][^'"`]+['"`]/gi,
    /\$\.(get|post|put|delete|patch|ajax)\s*\(\s*['"`][^'"`]+['"`]/gi, // jQuery Ajax calls
    /new\s+XMLHttpRequest\(\)/gi // Raw XHR objects
  ],
  
  // Auth tokens and API keys
  secrets: [
    /['"`](api[_-]?key|api[_-]?secret|app[_-]?key|app[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)['"]\s*[:=]\s*['"`][^\s'"`]{8,}['"`]/gi,
    /const\s+\w+key\s*=\s*['"`][^\s'"`]{8,}['"`]/gi,
    /const\s+\w+token\s*=\s*['"`][^\s'"`]{8,}['"`]/gi,
    /const\s+\w+secret\s*=\s*['"`][^\s'"`]{8,}['"`]/gi,
    /Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+/gi, // JWT pattern
    /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi, // Raw JWT pattern
    /['"`][a-zA-Z0-9]{32,}['"`]/gi, // Potential API keys (32+ chars)
    /['"`]sk_live_[0-9a-zA-Z]{24,}['"`]/gi, // Stripe live key pattern
    /['"`]pk_live_[0-9a-zA-Z]{24,}['"`]/gi  // Stripe publishable key pattern
  ],
  
  // Cloud provider keys
  cloudKeys: [
    /['"`]AKIA[0-9A-Z]{16}['"`]/g, // AWS Access Key ID
    /['"`][0-9a-zA-Z/+]{40}['"`]/g, // Potential AWS Secret Access Key
    /['"`]AIza[0-9A-Za-z-_]{35}['"`]/g, // Google API Key
    /['"`]ya29\.[0-9A-Za-z_-]+['"`]/g, // Google OAuth
    /['"`][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"`]/g, // Azure Key / UUID pattern
    /['"`]AC[a-zA-Z0-9]{32}['"`]/g, // Twilio API Key
    /['"`]SK[a-zA-Z0-9]{32}['"`]/g  // Twilio Secret Key
  ],
  
  // Hardcoded credentials
  credentials: [
    /['"`](username|user|login|password|passwd|pwd)['"`]\s*[:=]\s*['"`][^'"`\s]+['"`]/gi,
    /['"`](pass|password|passwd|pwd)['"`]\s*[:=]\s*['"`][^'"`\s]+['"`]/gi,
    /authorization:\s*['"`]Basic\s+[A-Za-z0-9+/=]+['"`]/gi, // Basic Auth
    /authToken\s*[:=]\s*['"`][^'"`\s]+['"`]/gi,
    /auth_token\s*[:=]\s*['"`][^'"`\s]+['"`]/gi
  ],
  
  // URLs and endpoints
  urls: [
    /['"`]https?:\/\/[^'"`\s]{4,}['"`]/gi,
    /http\.?:\/\/[^'"`\s]{4,}['"`]/gi,
    /['"`]\/\/[^'"`\s]+\.[a-z]{2,}\/[^'"`\s]*['"`]/gi, // Protocol-relative URLs
    /['"`](internal|admin|dashboard|management)[^'"`\s]*['"`]/gi // Internal endpoints
  ],
  
  // Config and environment variables
  configVars: [
    /process\.env\.[\w_]+/g,
    /config\.get\(\s*['"`][\w_.]+['"`]\s*\)/g,
    /secrets\.[\w_]+/g,
    /REACT_APP_[A-Z_]+/g,
    /NEXT_PUBLIC_[A-Z_]+/g,
    /VUE_APP_[A-Z_]+/g
  ],
  
  // Security vulnerability patterns for bug bounty
  securityVulnerabilities: [
    /document\.write\([^)]+\)/g, // Potential XSS
    /\$\(['"]\s*\#[^'"]+['"]\s*\)\.html\([^)]+\)/g, // jQuery XSS
    /innerHTML\s*=\s*[^;]+/g, // Direct innerHTML manipulation
    /eval\s*\([^)]+\)/g, // eval usage
    /new\s+Function\s*\([^)]+\)/g, // Dynamic function creation
    /setTimeout\s*\(\s*['"`][^'"`]+['"`]/g, // setTimeout with string
    /setInterval\s*\(\s*['"`][^'"`]+['"`]/g, // setInterval with string
    /location\s*\.\s*(href|hash|search|pathname)\s*=\s*/g, // Location redirects
    /window\.open\s*\([^)]+\)/g, // Window open calls
    /localStorage\s*\.\s*setItem\s*\([^)]+\)/g, // LocalStorage usage
    /sessionStorage\s*\.\s*setItem\s*\([^)]+\)/g, // SessionStorage usage
    /\.postMessage\s*\([^)]+\)/g, // PostMessage calls
    /\.addEventListener\s*\(\s*['"`]message['"`]/g, // Message listeners
    /\.(execCommand|insertAdjacentHTML)\s*\([^)]+\)/g, // DOM manipulation methods
    /new\s+WebSocket\s*\([^)]+\)/g // WebSocket connections
  ],
  
  // SSRF and open redirects
  ssrfVectors: [
    /\.(fetch|get|post)\s*\(\s*[^)]*\$\{/g, // Template literals in URLs
    /\.(fetch|get|post)\s*\(\s*[^)]*\+\s*/g, // String concatenation in URLs
    /url\s*[:=]\s*['"`][^'"`]+['"`]\s*\+\s*/g, // URL parameter concatenation
    /redirect\w*\s*[:=]\s*['"`][^'"`]+['"`]/g, // Redirect parameters
    /return_to\s*[:=]\s*['"`][^'"`]+['"`]/g, // Return_to parameters
    /callback\s*[:=]\s*['"`][^'"`]+['"`]/g // Callback parameters
  ],
  
  // GraphQL endpoints and operations
  graphql: [
    /\/graphql/g, // GraphQL endpoints
    /\/graph\-ql/g,
    /\.executeQuery\s*\(/g,
    /\.executeOperation\s*\(/g,
    /ApolloClient/g,
    /gql\s*`[^`]+`/g, // GraphQL queries
    /query\s*\w+\s*{[^}]+}/g,
    /mutation\s*\w+\s*{[^}]+}/g
  ],
  
  // Websocket endpoints
  websockets: [
    /new\s+WebSocket\s*\(\s*['"`][^'"`]+['"`]/g,
    /\.onmessage\s*=/g,
    /\.send\s*\([^)]+\)/g,
    /socket\.io/g,
    /\/ws\//g,
    /\/wss\//g,
    /\/socket\//g
  ],
  
  // Debug endpoints or dev features
  debugFeatures: [
    /\/debug\//g,
    /\/test\//g,
    /isDebug\s*[:=]\s*true/g,
    /isDevelopment\s*[:=]\s*true/g,
    /debugger/g,
    /console\.(log|debug|info|warn|error)/g,
    /\/dev\//g,
    /\/internal\//g,
    /env\s*[:=]\s*['"`]development['"`]/g
  ]
};

// Result storage
const results = {
  apiEndpoints: new Set(),
  secrets: new Set(),
  cloudKeys: new Set(),
  credentials: new Set(),
  urls: new Set(),
  configVars: new Set(),
  securityVulnerabilities: new Set(),
  ssrfVectors: new Set(),
  graphql: new Set(),
  websockets: new Set(),
  debugFeatures: new Set()
};

// File extensions to analyze
const TARGET_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.json', '.map'];

/**
 * Analyze a single file for sensitive information
 * @param {string} filePath - Path to the file to analyze
 * @returns {Promise<void>}
 */
async function analyzeFile(filePath) {
  return new Promise((resolve, reject) => {
    try {
      const fileStream = fs.createReadStream(filePath);
      const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
      });
      
      let lineNumber = 0;
      let fileContent = ''; // Store file content for full-file analysis
      
      rl.on('line', (line) => {
        lineNumber++;
        fileContent += line + '\n';
        
        // Check each pattern category
        for (const [category, patterns] of Object.entries(PATTERNS)) {
          for (const pattern of patterns) {
            const matches = [...line.matchAll(pattern)];
            if (matches.length > 0) {
              matches.forEach(match => {
                results[category].add({
                  file: filePath,
                  line: lineNumber,
                  content: match[0],
                  context: line.trim(),
                  severity: getSeverity(category, match[0])
                });
              });
            }
          }
        }
      });
      
      rl.on('close', () => {
        // Perform whole-file analysis for patterns that might span multiple lines
        analyzeWholeFile(filePath, fileContent);
        resolve();
      });
      
      rl.on('error', (err) => {
        reject(err);
      });
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * Analyze the entire file content for patterns that might span multiple lines
 * @param {string} filePath - Path to the file analyzed
 * @param {string} content - The entire file content
 */
function analyzeWholeFile(filePath, content) {
  // Check for multiline GraphQL queries
  const graphqlQueries = content.match(/gql\s*`[\s\S]+?`/g) || [];
  graphqlQueries.forEach(query => {
    results.graphql.add({
      file: filePath,
      line: "Multiline",
      content: query.length > 100 ? query.substring(0, 100) + "..." : query,
      context: "GraphQL query definition",
      severity: "Medium"
    });
  });
  
  // Check for endpoint mapping patterns like routers
  const routeDefinitions = content.match(/\.route\(\s*['"`][^'"`]+['"`]/g) || [];
  routeDefinitions.forEach(route => {
    results.apiEndpoints.add({
      file: filePath,
      line: "Multiline",
      content: route,
      context: "Express/Router endpoint definition",
      severity: "Medium"
    });
  });
}

/**
 * Determine the severity of a finding based on category and content
 * @param {string} category - Category of the finding
 * @param {string} content - The matched content
 * @returns {string} - Severity level (High, Medium, Low, Info)
 */
function getSeverity(category, content) {
  if (category === 'credentials' || 
      (category === 'secrets' && content.includes('_key')) || 
      (category === 'cloudKeys')) {
    return "High";
  } else if (category === 'securityVulnerabilities' || 
            category === 'ssrfVectors') {
    return "Medium";
  } else if (category === 'apiEndpoints' || 
            category === 'graphql' || 
            category === 'websockets') {
    return "Medium";
  } else {
    return "Low";
  }
}

/**
 * Recursively walk a directory to find JavaScript files
 * @param {string} dir - Directory to scan
 * @param {function} callback - Callback for each file found
 */
function walkDir(dir, callback) {
  fs.readdirSync(dir).forEach(f => {
    const dirPath = path.join(dir, f);
    const isDirectory = fs.statSync(dirPath).isDirectory();
    if (isDirectory) {
      walkDir(dirPath, callback);
    } else {
      const ext = path.extname(f).toLowerCase();
      if (TARGET_EXTENSIONS.includes(ext)) {
        callback(path.join(dir, f));
      }
    }
  });
}

/**
 * Format the results for output
 * @param {Object} results - Collection of findings
 * @returns {string} - Formatted markdown output
 */
function formatResults(results) {
  let output = '# JavaScript Security Analysis & Bug Bounty Report\n\n';
  output += `*Generated on: ${new Date().toISOString()}*\n\n`;
  output += '## Executive Summary\n\n';
  
  // Calculate total findings and by severity
  let totalFindings = 0;
  let highSeverity = 0;
  let mediumSeverity = 0;
  let lowSeverity = 0;
  
  for (const findings of Object.values(results)) {
    findings.forEach(finding => {
      totalFindings++;
      if (finding.severity === "High") highSeverity++;
      else if (finding.severity === "Medium") mediumSeverity++;
      else lowSeverity++;
    });
  }
  
  output += `Total findings: **${totalFindings}**\n\n`;
  output += `- High severity: **${highSeverity}**\n`;
  output += `- Medium severity: **${mediumSeverity}**\n`;
  output += `- Low severity: **${lowSeverity}**\n\n`;
  
  // Add findings by category
  for (const [category, findings] of Object.entries(results)) {
    if (findings.size === 0) continue;
    
    output += `## ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`;
    
    const findingsArray = Array.from(findings);
    // Sort by severity (High → Medium → Low)
    findingsArray.sort((a, b) => {
      const severityOrder = { "High": 0, "Medium": 1, "Low": 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
    
    findingsArray.forEach((finding, index) => {
      output += `### ${category} ${index + 1} (${finding.severity} Severity)\n`;
      output += `- **File**: ${finding.file}\n`;
      output += `- **Line**: ${finding.line}\n`;
      output += `- **Match**: \`${finding.content}\`\n`;
      output += `- **Context**: \`${finding.context}\`\n`;
      
      // Add specific remediation advice based on finding category
      output += `- **Potential Risk**: ${getSecurityRisk(category, finding.content)}\n`;
      output += `- **Remediation**: ${getRemediationAdvice(category, finding.content)}\n\n`;
    });
  }
  
  return output;
}

/**
 * Generate JSON output for the results
 * @param {Object} results - Collection of findings
 * @returns {string} - JSON string
 */
function formatResultsJSON(results) {
  const jsonResults = {};
  
  for (const [category, findings] of Object.entries(results)) {
    if (findings.size === 0) continue;
    
    jsonResults[category] = Array.from(findings).map(finding => ({
      file: finding.file,
      line: finding.line,
      content: finding.content,
      context: finding.context,
      severity: finding.severity,
      risk: getSecurityRisk(category, finding.content),
      remediation: getRemediationAdvice(category, finding.content)
    }));
  }
  
  return JSON.stringify(jsonResults, null, 2);
}

/**
 * Get security risk description based on finding category
 * @param {string} category - Category of the finding
 * @param {string} content - The matched content
 * @returns {string} - Risk description
 */
function getSecurityRisk(category, content) {
  switch (category) {
    case 'apiEndpoints':
      return "Exposed API endpoints could reveal application structure or be targeted for attack";
    case 'secrets':
      return "Hardcoded secrets may be exposed if source code is leaked or client-side code is inspected";
    case 'cloudKeys':
      return "Cloud provider keys could grant unauthorized access to services and resources";
    case 'credentials':
      return "Hardcoded credentials risk unauthorized access if compromised";
    case 'securityVulnerabilities':
      if (content.includes('innerHTML') || content.includes('document.write'))
        return "Potential XSS vulnerability from unsafe DOM manipulation";
      if (content.includes('eval'))
        return "Code injection risk from use of eval()";
      return "Security vulnerability that could be exploited by attackers";
    case 'ssrfVectors':
      return "Potential SSRF or open redirect vulnerability from URL manipulation";
    default:
      return "Information disclosure or potential security weakness";
  }
}

/**
 * Get remediation advice based on finding category
 * @param {string} category - Category of the finding
 * @param {string} content - The matched content
 * @returns {string} - Remediation advice
 */
function getRemediationAdvice(category, content) {
  switch (category) {
    case 'apiEndpoints':
      return "Ensure proper authentication and authorization controls on API endpoints";
    case 'secrets':
    case 'cloudKeys':
      return "Move sensitive values to environment variables or secure vaults, avoid client-side storage";
    case 'credentials':
      return "Remove hardcoded credentials and implement proper authentication flows";
    case 'securityVulnerabilities':
      if (content.includes('innerHTML') || content.includes('document.write'))
        return "Use safer alternatives like textContent or DOM manipulation methods, sanitize input";
      if (content.includes('eval'))
        return "Avoid using eval() and use safer alternatives";
      return "Review code for security implications and implement proper input validation";
    case 'ssrfVectors':
      return "Implement URL validation, whitelist allowed domains, and use indirect object references";
    default:
      return "Review the code and ensure sensitive information is properly protected";
  }
}

/**
 * Main function to run the analysis
 * @param {string} targetDir - Directory to analyze
 */
async function main(targetDir) {
  if (!targetDir) {
    console.error('Please provide a target directory');
    process.exit(1);
  }

  console.log(`Starting advanced security analysis of ${targetDir}...`);
  
  const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
  const outputFile = path.join(resultsDir, `js-security-report-${timestamp}.md`);
  const jsonOutputFile = path.join(resultsDir, `js-security-report-${timestamp}.json`);
  
  try {
    const files = [];
    walkDir(targetDir, (filePath) => {
      files.push(filePath);
    });
    
    console.log(`Found ${files.length} JavaScript/related files to analyze`);
    
    let processedFiles = 0;
    const totalFiles = files.length;
    
    for (const file of files) {
      await analyzeFile(file);
      processedFiles++;
      
      // Show progress
      if (processedFiles % 10 === 0 || processedFiles === totalFiles) {
        const percentage = ((processedFiles / totalFiles) * 100).toFixed(1);
        console.log(`Progress: ${processedFiles}/${totalFiles} files (${percentage}%)`);
      }
    }
    
    // Output results
    fs.writeFileSync(outputFile, formatResults(results));
    fs.writeFileSync(jsonOutputFile, formatResultsJSON(results));
    
    console.log(`Analysis complete! Results saved to:`);
    console.log(`- Markdown report: ${outputFile}`);
    console.log(`- JSON data: ${jsonOutputFile}`);
    
    // Print summary to console
    let totalFindings = 0;
    let highSeverity = 0;
    let mediumSeverity = 0;
    let lowSeverity = 0;
    
    for (const findings of Object.values(results)) {
      findings.forEach(finding => {
        totalFindings++;
        if (finding.severity === "High") highSeverity++;
        else if (finding.severity === "Medium") mediumSeverity++;
        else lowSeverity++;
      });
    }
    
    console.log(`\nSecurity Summary:`);
    console.log(`Total findings: ${totalFindings}`);
    console.log(`- High severity: ${highSeverity}`);
    console.log(`- Medium severity: ${mediumSeverity}`);
    console.log(`- Low severity: ${lowSeverity}`);
    
    for (const [category, findings] of Object.entries(results)) {
      if (findings.size > 0) {
        console.log(`- ${category}: ${findings.size} findings`);
      }
    }
  } catch (error) {
    console.error('Error during analysis:', error);
  }
}

// Allow running from command line
if (require.main === module) {
  const targetDir = process.argv[2] || '.';
  main(targetDir);
}

module.exports = {
  analyzeFile,
  walkDir,
  formatResults,
  formatResultsJSON,
  main
};
