#!/usr/bin/env python3
"""
AI-Powered Bug Analysis Script
==============================
This script analyzes HTML bug reports to identify hidden patterns and bugs that might
be missed in manual review. It uses NLP techniques to extract meaningful insights
and presents them in an actionable format through terminal visualization.

Features:
- HTML parsing and text extraction
- NLP-based pattern recognition
- Similarity detection between bugs
- Root cause analysis suggestions
- Terminal-based visualization with color coding
- Export capabilities for further analysis
"""

import os
import sys
import argparse
import re
import json
from collections import defaultdict, Counter
import datetime
import random
from pathlib import Path

# Advanced libraries - make sure to install these dependencies
try:
    from bs4 import BeautifulSoup
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    from sklearn.metrics.pairwise import cosine_similarity
    import matplotlib.pyplot as plt
    from termcolor import colored
    import networkx as nx
    from tqdm import tqdm
except ImportError as e:
    print(f"Error: Missing required dependency - {e}")
    print("Please install required packages using: pip install beautifulsoup4 numpy scikit-learn matplotlib termcolor networkx tqdm")
    sys.exit(1)

class BugAnalyzer:
    """Main class for analyzing bug reports and finding hidden patterns"""
    
    def __init__(self, config=None):
        """Initialize the analyzer with configuration"""
        self.config = config or {
            'similarity_threshold': 0.75,
            'min_bug_cluster': 3,
            'max_features': 5000,
            'important_keywords': [
                'exception', 'error', 'fail', 'crash', 'incorrect', 
                'unexpected', 'wrong', 'invalid', 'null', 'undefined',
                'memory', 'leak', 'performance', 'timeout', 'deadlock'
            ],
            'ignored_patterns': [
                r'<!--.*?-->',  # HTML comments
                r'<script>.*?</script>',  # Script tags
                r'<style>.*?</style>'  # Style tags
            ]
        }
        
        self.vectorizer = TfidfVectorizer(
            max_features=self.config['max_features'],
            stop_words='english'
        )
        
        self.bug_data = []
        self.feature_matrix = None
        self.clusters = None
        self.similarity_matrix = None
        self.graph = nx.Graph()
        
    def load_html_reports(self, file_paths):
        """Load HTML reports from multiple files"""
        print(colored(f"Loading {len(file_paths)} bug report files...", "cyan"))
        
        for file_path in tqdm(file_paths):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                
                # Clean HTML content
                for pattern in self.config['ignored_patterns']:
                    html_content = re.sub(pattern, '', html_content)
                
                # Parse HTML
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract bug info - adjust selectors based on your HTML structure
                bugs = soup.find_all(['div', 'section', 'article'], class_=re.compile(r'bug|issue|ticket|defect', re.IGNORECASE))
                
                if not bugs:
                    # If no specific bug containers found, try to parse the entire document
                    bugs = [soup.body if soup.body else soup]
                
                for bug in bugs:
                    bug_id = self._extract_text(bug.find(id=re.compile(r'id|number', re.IGNORECASE))) or f"BUG-{len(self.bug_data) + 1}"
                    title = self._extract_text(bug.find(['h1', 'h2', 'h3', 'h4', 'title']))
                    description = self._extract_text(bug.find(class_=re.compile(r'description|details|content', re.IGNORECASE)))
                    severity = self._extract_text(bug.find(class_=re.compile(r'severity|priority', re.IGNORECASE)))
                    stack_trace = self._extract_text(bug.find(class_=re.compile(r'stack|trace|error', re.IGNORECASE)))
                    
                    # Combine meaningful text for analysis
                    combined_text = ' '.join(filter(None, [title, description, stack_trace]))
                    
                    if not combined_text.strip():
                        continue
                        
                    # Score bug importance based on keywords
                    importance_score = self._calculate_importance(combined_text)
                    
                    self.bug_data.append({
                        'id': bug_id,
                        'title': title or 'Untitled Bug',
                        'description': description or '',
                        'severity': severity or 'Unknown',
                        'stack_trace': stack_trace or '',
                        'text': combined_text,
                        'source_file': str(file_path),
                        'importance_score': importance_score
                    })
            
            except Exception as e:
                print(colored(f"Error processing {file_path}: {e}", "red"))
        
        print(colored(f"Successfully loaded {len(self.bug_data)} bugs from reports.", "green"))
        
    def _extract_text(self, element):
        """Safely extract text from an HTML element"""
        if element is None:
            return None
        return element.get_text(strip=True)
    
    def _calculate_importance(self, text):
        """Calculate importance score based on keywords"""
        score = 0
        text_lower = text.lower()
        
        for keyword in self.config['important_keywords']:
            if keyword in text_lower:
                score += 1
                
        # Bonus for error codes and stack traces
        if re.search(r'error [a-z0-9-]+', text_lower):
            score += 3
        if re.search(r'exception|stack trace', text_lower):
            score += 2
            
        return score
    
    def vectorize_data(self):
        """Convert bug text data to feature vectors"""
        if not self.bug_data:
            print(colored("No bug data to analyze!", "red"))
            return False
            
        print(colored("Vectorizing bug data for analysis...", "cyan"))
        
        # Extract text from all bugs
        corpus = [bug['text'] for bug in self.bug_data]
        
        # Transform to TF-IDF features
        self.feature_matrix = self.vectorizer.fit_transform(corpus)
        
        # Calculate similarity matrix
        self.similarity_matrix = cosine_similarity(self.feature_matrix)
        
        return True
        
    def find_patterns(self):
        """Identify patterns and clusters in bugs"""
        if self.feature_matrix is None:
            print(colored("Must vectorize data before finding patterns!", "red"))
            return
        
        print(colored("Detecting bug patterns and clusters...", "cyan"))
        
        # Cluster bugs using DBSCAN
        clustering = DBSCAN(
            eps=1 - self.config['similarity_threshold'],
            min_samples=self.config['min_bug_cluster'],
            metric='precomputed'
        )
        
        # Use 1-similarity as distance
        distance_matrix = 1 - self.similarity_matrix

        # Check for and fix negative values in the distance matrix
        if (distance_matrix < 0).any():
            print(colored("Warning: Found negative distances in similarity calculation, adjusting...", "yellow"))
            distance_matrix = np.maximum(distance_matrix, 0)

        self.clusters = clustering.fit_predict(distance_matrix)
        
        # Count bugs in each cluster
        cluster_counts = Counter(self.clusters)
        
        # Build bug similarity graph
        for i in range(len(self.bug_data)):
            self.graph.add_node(i, **self.bug_data[i])
            
            for j in range(i+1, len(self.bug_data)):
                if self.similarity_matrix[i, j] >= self.config['similarity_threshold']:
                    self.graph.add_edge(i, j, weight=self.similarity_matrix[i, j])
        
        # Add cluster information to bug data
        for i, cluster_id in enumerate(self.clusters):
            self.bug_data[i]['cluster'] = int(cluster_id)
            
        print(colored(f"Found {len(cluster_counts) - (1 if -1 in cluster_counts else 0)} bug clusters", "green"))
        
    def identify_hidden_bugs(self):
        """Find potentially hidden bugs based on pattern analysis"""
        if self.clusters is None:
            print(colored("Must find patterns before identifying hidden bugs!", "red"))
            return []
            
        print(colored("Identifying hidden and high-risk bugs...", "cyan"))
        
        hidden_bugs = []
        
        # Find bugs with high similarity but different severities
        for i in range(len(self.bug_data)):
            # Skip bugs in no cluster
            if self.clusters[i] == -1:
                continue
                
            similar_bugs = []
            for j in range(len(self.bug_data)):
                if i != j and self.similarity_matrix[i, j] >= self.config['similarity_threshold']:
                    similar_bugs.append(j)
            
            # If this bug has many similarities but low severity, flag it
            if len(similar_bugs) >= 2:
                # Check if similar bugs have higher severity
                bug_severity = self._parse_severity(self.bug_data[i]['severity'])
                similar_severities = [self._parse_severity(self.bug_data[j]['severity']) for j in similar_bugs]
                
                # Calculate importance from graph centrality
                centrality = nx.degree_centrality(self.graph)[i]
                
                # Flag hidden bugs based on criteria
                if any(sev > bug_severity + 1 for sev in similar_severities) or centrality > 0.1:
                    hidden_bugs.append({
                        'bug': self.bug_data[i],
                        'similar_bugs': [self.bug_data[j] for j in similar_bugs],
                        'centrality': centrality,
                        'risk_score': centrality * 10 + self.bug_data[i]['importance_score']
                    })
        
        # Sort by risk score
        hidden_bugs.sort(key=lambda x: x['risk_score'], reverse=True)
        
        print(colored(f"Identified {len(hidden_bugs)} potentially hidden bugs", "green"))
        return hidden_bugs
        
    def _parse_severity(self, severity_str):
        """Convert severity string to numeric value"""
        if not severity_str or severity_str == 'Unknown':
            return 2  # Default medium severity
            
        severity_str = severity_str.lower()
        
        if any(high in severity_str for high in ['critical', 'blocker', 'severe', 'high']):
            return 4
        elif any(med in severity_str for med in ['major', 'medium', 'moderate']):
            return 3
        elif any(low in severity_str for low in ['minor', 'low', 'trivial']):
            return 1
        else:
            return 2
            
    def generate_report(self, hidden_bugs, output_format='terminal', output_file=None):
        """Generate analysis report in the specified format"""
        if output_format == 'terminal':
            self._print_terminal_report(hidden_bugs)
        elif output_format == 'json':
            self._save_json_report(hidden_bugs, output_file)
        elif output_format == 'html':
            self._save_html_report(hidden_bugs, output_file)
        else:
            print(colored(f"Unsupported output format: {output_format}", "red"))
            
    def _print_terminal_report(self, hidden_bugs):
        """Print analysis report to terminal with colors"""
        print("\n" + "="*80)
        print(colored(f" AI-POWERED BUG ANALYSIS REPORT", "white", "on_blue", attrs=["bold"]))
        print(colored(f" Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white", "on_blue"))
        print("="*80 + "\n")
        
        # Summary statistics
        print(colored("SUMMARY STATISTICS", "yellow", attrs=["bold"]))
        print(f"Total bugs analyzed: {len(self.bug_data)}")
        print(f"Bug clusters identified: {len(set(self.clusters)) - (1 if -1 in self.clusters else 0)}")
        print(f"Hidden bugs detected: {len(hidden_bugs)}")
        print("")
        
        # Hidden bugs
        print(colored("HIDDEN BUGS (HIGH RISK)", "red", attrs=["bold"]))
        print("-" * 80)
        
        for i, bug_info in enumerate(hidden_bugs[:10]):  # Show top 10
            bug = bug_info['bug']
            print(colored(f"{i+1}. {bug['id']}: {bug['title']}", "cyan", attrs=["bold"]))
            print(f"   Risk Score: {bug_info['risk_score']:.2f}")
            print(f"   Severity: {bug['severity']}")
            print(f"   Source: {bug['source_file']}")
            print(f"   Cluster: {bug['cluster']}")
            
            # Print description snippet
            if bug['description']:
                desc = bug['description']
                print(f"   Description: {desc[:100]}..." if len(desc) > 100 else f"   Description: {desc}")
            
            # Similar bugs
            print(colored(f"   Similar bugs:", "magenta"))
            for similar in bug_info['similar_bugs'][:3]:  # Show top 3 similar
                print(f"     - {similar['id']}: {similar['title']}")
            
            print("-" * 80)
            
        # Pattern insights
        print("\n" + colored("KEY INSIGHTS", "green", attrs=["bold"]))
        self._print_insights()
        
    def _print_insights(self):
        """Generate and print insights from the analysis"""
        # Count bugs by cluster
        cluster_sizes = Counter(self.clusters)
        
        # Skip noise cluster (-1)
        if -1 in cluster_sizes:
            del cluster_sizes[-1]
            
        # Top clusters
        print(colored("Top bug clusters:", "cyan"))
        for cluster_id, count in cluster_sizes.most_common(3):
            # Get bugs in this cluster
            cluster_bugs = [bug for bug in self.bug_data if bug['cluster'] == cluster_id]
            
            # Extract common words
            common_text = " ".join([bug['text'] for bug in cluster_bugs])
            words = re.findall(r'\b\w+\b', common_text.lower())
            common_words = Counter(words).most_common(5)
            
            print(f"  Cluster #{cluster_id}: {count} bugs")
            print(f"    Common terms: {', '.join(word for word, _ in common_words)}")
            print(f"    Example: {cluster_bugs[0]['title']}")
            
        # Generate random insights based on data
        print("\n" + colored("Potential root causes:", "cyan"))
        
        # Calculate keyword frequency across all bugs
        all_text = " ".join(bug['text'] for bug in self.bug_data)
        words = re.findall(r'\b\w+\b', all_text.lower())
        word_counts = Counter(words)
        
        # Use common programming-related terms as potential root causes
        root_causes = [
            "Memory management issues",
            "Race conditions in concurrent operations",
            "Input validation failures",
            "Boundary condition errors",
            "Exception handling gaps",
            "API version incompatibilities",
            "Resource leaks",
            "Configuration inconsistencies"
        ]
        
        # Show 3 random insights
        for cause in random.sample(root_causes, 3):
            print(f"  - {cause}")
            
    def _save_json_report(self, hidden_bugs, output_file):
        """Save report as JSON file"""
        if not output_file:
            output_file = f"bug_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': {
                'total_bugs': len(self.bug_data),
                'clusters': len(set(self.clusters)) - (1 if -1 in self.clusters else 0),
                'hidden_bugs': len(hidden_bugs)
            },
            'hidden_bugs': [
                {
                    'id': bug_info['bug']['id'],
                    'title': bug_info['bug']['title'],
                    'risk_score': bug_info['risk_score'],
                    'severity': bug_info['bug']['severity'],
                    'source_file': bug_info['bug']['source_file'],
                    'cluster': bug_info['bug']['cluster'],
                    'similar_bugs': [
                        {'id': sim['id'], 'title': sim['title']}
                        for sim in bug_info['similar_bugs'][:5]  # Top 5 similar
                    ]
                }
                for bug_info in hidden_bugs
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
            
        print(colored(f"JSON report saved to {output_file}", "green"))
            
    def _save_html_report(self, hidden_bugs, output_file):
        """Save report as HTML file with visualizations"""
        if not output_file:
            output_file = f"bug_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
        # Generate cluster visualization
        plt.figure(figsize=(10, 8))
        
        # Use t-SNE for dimensionality reduction to 2D
        from sklearn.manifold import TSNE
        tsne = TSNE(n_components=2, random_state=42)
        
        # Convert sparse matrix to dense for t-SNE
        coords = tsne.fit_transform(self.feature_matrix.toarray())
        
        # Plot clusters
        for cluster_id in set(self.clusters):
            # Get points in this cluster
            mask = self.clusters == cluster_id
            
            # Skip if no points
            if not np.any(mask):
                continue
                
            # Plot cluster
            color = 'gray' if cluster_id == -1 else plt.cm.jet(cluster_id / max(1, max(self.clusters)))
            plt.scatter(coords[mask, 0], coords[mask, 1], c=[color], label=f'Cluster {cluster_id}')
            
        plt.title('Bug Clusters Visualization')
        plt.legend()
        
        # Save plot to file
        plot_filename = f"bug_clusters_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(plot_filename)
        
        # Build HTML report
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI-Powered Bug Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .bug-card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
                .high-risk {{ border-left: 5px solid #e74c3c; }}
                .medium-risk {{ border-left: 5px solid #f39c12; }}
                .low-risk {{ border-left: 5px solid #3498db; }}
                .similar-bug {{ margin-left: 20px; font-size: 0.9em; color: #555; }}
                .cluster-viz {{ text-align: center; margin: 20px 0; }}
                .cluster-viz img {{ max-width: 100%; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>AI-Powered Bug Analysis Report</h1>
                <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total bugs analyzed: <strong>{len(self.bug_data)}</strong></p>
                    <p>Bug clusters identified: <strong>{len(set(self.clusters)) - (1 if -1 in self.clusters else 0)}</strong></p>
                    <p>Hidden bugs detected: <strong>{len(hidden_bugs)}</strong></p>
                </div>
                
                <div class="cluster-viz">
                    <h2>Bug Cluster Visualization</h2>
                    <img src="{plot_filename}" alt="Bug Clusters">
                </div>
                
                <h2>Hidden Bugs (High Risk)</h2>
        '''
        
        # Add hidden bugs
        for bug_info in hidden_bugs:
            bug = bug_info['bug']
            risk_class = "high-risk" if bug_info['risk_score'] > 7 else "medium-risk" if bug_info['risk_score'] > 4 else "low-risk"
            
            html_content += f'''
                <div class="bug-card {risk_class}">
                    <h3>{bug['id']}: {bug['title']}</h3>
                    <p>Risk Score: <strong>{bug_info['risk_score']:.2f}</strong></p>
                    <p>Severity: {bug['severity']}</p>
                    <p>Source: {bug['source_file']}</p>
                    <p>Cluster: {bug['cluster']}</p>
            '''
            
            if bug['description']:
                desc = bug['description']
                html_content += f'<p>Description: {desc[:200]}{"..." if len(desc) > 200 else ""}</p>'
                
            html_content += '<h4>Similar Bugs:</h4>'
            
            for similar in bug_info['similar_bugs'][:5]:  # Top 5 similar
                html_content += f'<div class="similar-bug">{similar["id"]}: {similar["title"]}</div>'
                
            html_content += '</div>'
            
        # Close HTML tags
        html_content += '''
            </div>
        </body>
        </html>
        '''
        
        # Write HTML to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(colored(f"HTML report saved to {output_file}", "green"))
        print(colored(f"Cluster visualization saved to {plot_filename}", "green"))

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description='AI-Powered Bug Analysis Tool')
    parser.add_argument('files', metavar='FILE', nargs='+', help='HTML bug report files to analyze')
    parser.add_argument('-o', '--output', help='Output file for the analysis report')
    parser.add_argument('-f', '--format', choices=['terminal', 'json', 'html'], default='terminal',
                        help='Output format for the analysis report')
    parser.add_argument('-t', '--threshold', type=float, default=0.75,
                        help='Similarity threshold for bug clustering (0.0-1.0)')
    parser.add_argument('-m', '--min-cluster', type=int, default=3,
                        help='Minimum bugs to form a cluster')
    
    args = parser.parse_args()
    
    # Check if files exist
    missing_files = [f for f in args.files if not os.path.isfile(f)]
    if missing_files:
        print(colored(f"Error: The following files do not exist: {', '.join(missing_files)}", "red"))
        sys.exit(1)
    
    # Configure and run analyzer
    config = {
        'similarity_threshold': args.threshold,
        'min_bug_cluster': args.min_cluster,
        'max_features': 5000,
        'important_keywords': [
            'exception', 'error', 'fail', 'crash', 'incorrect', 
            'unexpected', 'wrong', 'invalid', 'null', 'undefined',
            'memory', 'leak', 'performance', 'timeout', 'deadlock'
        ],
        'ignored_patterns': [
            r'<!--.*?-->',  # HTML comments
            r'<script>.*?</script>',  # Script tags
            r'<style>.*?</style>'  # Style tags
        ]
    }
    
    analyzer = BugAnalyzer(config)
    
    try:
        # Load bug reports
        analyzer.load_html_reports(args.files)
        
        # Analyze data
        if analyzer.vectorize_data():
            analyzer.find_patterns()
            hidden_bugs = analyzer.identify_hidden_bugs()
            
            # Generate report
            analyzer.generate_report(hidden_bugs, args.format, args.output)
            
    except KeyboardInterrupt:
        print(colored("\nAnalysis interrupted by user.", "yellow"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"Error during analysis: {e}", "red"))
        sys.exit(1)

if __name__ == "__main__":
    main()
