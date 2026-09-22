# Project Analysis Summary Report (Full Version)

Generation Time: 2026-09-22 01:11:10 UTC

## Execution Timing Statistics

- **Total Execution Time**: 82.97 seconds
- **Preprocessing Phase**: 0.02 seconds (0.0%)
- **Research Phase**: 0.00 seconds (0.0%)
- **Document Generation Phase**: 82.95 seconds (100.0%)
- **Output Phase**: 0.00 seconds (0.0%)
- **Summary Generation Time**: 0.000 seconds

## Cache Performance Statistics and Savings

### Performance Metrics
- **Cache Hit Rate**: 76.7%
- **Total Operations**: 30
- **Cache Hits**: 23 times
- **Cache Misses**: 7 times
- **Cache Writes**: 8 times

### Savings
- **Inference Time Saved**: 144.3 seconds
- **Tokens Saved**: 52973 input + 20071 output = 73044 total
- **Estimated Cost Savings**: $0.0420
- **Performance Improvement**: 76.7%
- **Efficiency Improvement Ratio**: 1.7x (saved time / actual execution time)

## Core Research Data Summary

Complete content of four types of research materials according to Prompt template data integration rules:

### System Context Research Report
Provides core objectives, user roles, and system boundary information for the project.

```json
{
  "business_value": "Sentari offers automated security assessments, improving efficiency and accuracy in identifying vulnerabilities. It supports integration with AI providers for advanced analysis and provides a web interface for easy result visualization.",
  "confidence_score": 9.0,
  "external_systems": [
    {
      "description": "Database system for storing assessment data.",
      "interaction_type": "Data Storage",
      "name": "PostgreSQL"
    },
    {
      "description": "In-memory data structure store used for caching and message brokering.",
      "interaction_type": "Caching and Message Brokering",
      "name": "Redis"
    },
    {
      "description": "External AI services like OpenAI and Google for advanced analysis.",
      "interaction_type": "API Integration",
      "name": "AI Providers"
    }
  ],
  "project_description": "Sentari is a security assessment tool that provides a command-line interface for executing various security assessment phases. It includes modules for reconnaissance, scanning, vulnerability assessment, and reporting. The tool supports distributed task execution using Celery and provides a web dashboard for viewing assessment results.",
  "project_name": "sentari",
  "project_type": "CLITool",
  "system_boundary": {
    "excluded_components": [
      "External AI Providers",
      "Third-party Security Tools"
    ],
    "included_components": [
      "CLI",
      "Web Dashboard",
      "Task Management",
      "Security Phases",
      "Reporting"
    ],
    "scope": "Sentari includes components for security assessments, task management, and result reporting. It excludes external tool execution and AI provider management."
  },
  "target_users": [
    {
      "description": "Professionals responsible for assessing and improving the security posture of systems.",
      "name": "Security Analysts",
      "needs": [
        "Automated security assessments",
        "Detailed vulnerability reports",
        "Integration with existing security tools"
      ]
    },
    {
      "description": "Engineers focused on integrating security assessments into CI/CD pipelines.",
      "name": "DevOps Engineers",
      "needs": [
        "Command-line tool for automation",
        "Scalable task execution",
        "Integration with Kubernetes and Docker"
      ]
    }
  ]
}
```

### Domain Modules Research Report
Provides high-level domain division, module relationships, and core business process information.

```json
{
  "architecture_summary": "The Sentari architecture is designed around core business domains that handle security assessments, AI integration, task management, reporting, and web interface functionalities. The system leverages a modular approach, allowing for distributed task execution and integration with external AI providers. The architecture supports scalability and flexibility, with a focus on providing comprehensive security assessments and easy result visualization.",
  "business_flows": [
    {
      "description": "Executes a full security assessment including reconnaissance, scanning, and vulnerability assessment.",
      "entry_point": "/home/ahmad/Downloads/sentari/sentari/__main__.py",
      "importance": 9.0,
      "involved_domains_count": 1,
      "name": "Security Assessment Execution",
      "steps": [
        {
          "code_entry_point": "/home/ahmad/Downloads/sentari/sentari/phases/recon.py",
          "domain_module": "Security Assessment Domain",
          "operation": "Identify targets and perform basic web fingerprinting.",
          "step": 1,
          "sub_module": "Reconnaissance Phase"
        },
        {
          "code_entry_point": "/home/ahmad/Downloads/sentari/sentari/phases/scanning.py",
          "domain_module": "Security Assessment Domain",
          "operation": "Perform detailed scanning and enumeration.",
          "step": 2,
          "sub_module": "Scanning Phase"
        },
        {
          "code_entry_point": "/home/ahmad/Downloads/sentari/sentari/phases/vuln.py",
          "domain_module": "Security Assessment Domain",
          "operation": "Run vulnerability assessments and confirm findings.",
          "step": 3,
          "sub_module": "Vulnerability Assessment Phase"
        }
      ]
    },
    {
      "description": "Integrates AI analysis into the security assessment process.",
      "entry_point": "/home/ahmad/Downloads/sentari/sentari/ai/analyst.py",
      "importance": 8.0,
      "involved_domains_count": 1,
      "name": "AI-Enhanced Analysis",
      "steps": [
        {
          "code_entry_point": "/home/ahmad/Downloads/sentari/sentari/ai/providers.py",
          "domain_module": "AI Integration Domain",
          "operation": "Check availability of AI providers.",
          "step": 1,
          "sub_module": "AI Providers Management"
        },
        {
          "code_entry_point": "/home/ahmad/Downloads/sentari/sentari/ai/analyst.py",
          "domain_module": "AI Integration Domain",
          "operation": "Perform AI-based analysis.",
          "step": 2,
          "sub_module": "AI Analysis"
        }
      ]
    }
  ],
  "confidence_score": 9.0,
  "domain_modules": [
    {
      "code_paths": [
        "/home/ahmad/Downloads/sentari/sentari/phases/base.py",
        "/home/ahmad/Downloads/sentari/sentari/phases/__init__.py"
      ],
      "complexity": 8.0,
      "description": "Handles the execution of security assessments, including reconnaissance, scanning, and vulnerability assessment.",
      "domain_type": "Core Business Domain",
      "importance": 9.0,
      "name": "Security Assessment Domain",
      "sub_modules": [
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/phases/recon.py"
          ],
          "description": "Identifies existing targets, resolves IPs, and performs basic web fingerprinting.",
          "importance": 9.0,
          "key_functions": [
            "Identify targets",
            "Resolve IPs",
            "Web fingerprinting"
          ],
          "name": "Reconnaissance Phase"
        },
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/phases/scanning.py"
          ],
          "description": "Performs detailed scanning and enumeration of discovered web ports.",
          "importance": 9.0,
          "key_functions": [
            "Security header analysis",
            "TLS inspection",
            "Content discovery"
          ],
          "name": "Scanning Phase"
        },
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/phases/vuln.py"
          ],
          "description": "Runs vulnerability assessments using detection engines.",
          "importance": 9.0,
          "key_functions": [
            "Vulnerability detection",
            "Evidence-backed results"
          ],
          "name": "Vulnerability Assessment Phase"
        }
      ]
    },
    {
      "code_paths": [
        "/home/ahmad/Downloads/sentari/sentari/ai/__init__.py"
      ],
      "complexity": 7.0,
      "description": "Manages integration with AI providers for advanced analysis.",
      "domain_type": "Tool Support Domain",
      "importance": 8.0,
      "name": "AI Integration Domain",
      "sub_modules": [
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/ai/providers.py"
          ],
          "description": "Abstracts various AI providers under a unified interface.",
          "importance": 8.0,
          "key_functions": [
            "Check availability",
            "Perform completions"
          ],
          "name": "AI Providers Management"
        },
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/ai/analyst.py"
          ],
          "description": "Conducts AI-based analysis using grounded AI functionalities.",
          "importance": 8.0,
          "key_functions": [
            "Perform AI analysis",
            "Represent analysis results"
          ],
          "name": "AI Analysis"
        }
      ]
    },
    {
      "code_paths": [
        "/home/ahmad/Downloads/sentari/sentari/tasks/__init__.py"
      ],
      "complexity": 7.0,
      "description": "Handles distributed task execution using Celery.",
      "domain_type": "Infrastructure Domain",
      "importance": 8.0,
      "name": "Task Management Domain",
      "sub_modules": [
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py"
          ],
          "description": "Defines Celery tasks for running assessments.",
          "importance": 8.0,
          "key_functions": [
            "Define tasks",
            "Distributed execution"
          ],
          "name": "Celery Task Definition"
        },
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/tasks/app.py"
          ],
          "description": "Handles optional Celery application setup for distributed task execution.",
          "importance": 7.0,
          "key_functions": [
            "Setup Celery application"
          ],
          "name": "Celery Application Setup"
        }
      ]
    },
    {
      "code_paths": [
        "/home/ahmad/Downloads/sentari/sentari/reporting/__init__.py"
      ],
      "complexity": 6.0,
      "description": "Generates reports for security assessments.",
      "domain_type": "Core Business Domain",
      "importance": 7.0,
      "name": "Reporting Domain",
      "sub_modules": [
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/reporting/html.py"
          ],
          "description": "Generates self-contained HTML reports.",
          "importance": 7.0,
          "key_functions": [
            "Generate HTML reports"
          ],
          "name": "HTML Reporting"
        }
      ]
    },
    {
      "code_paths": [
        "/home/ahmad/Downloads/sentari/sentari/web/__init__.py"
      ],
      "complexity": 7.0,
      "description": "Provides a web dashboard and REST API for viewing assessment results.",
      "domain_type": "Core Business Domain",
      "importance": 8.0,
      "name": "Web Interface Domain",
      "sub_modules": [
        {
          "code_paths": [
            "/home/ahmad/Downloads/sentari/sentari/web/server.py"
          ],
          "description": "Implements a read-only web dashboard and REST API.",
          "importance": 8.0,
          "key_functions": [
            "Serve web dashboard",
            "Provide REST API"
          ],
          "name": "Web Dashboard"
        }
      ]
    }
  ],
  "domain_relations": [
    {
      "description": "Security assessments utilize AI providers for advanced analysis.",
      "from_domain": "Security Assessment Domain",
      "relation_type": "API Integration",
      "strength": 7.0,
      "to_domain": "AI Integration Domain"
    },
    {
      "description": "Tasks are executed to perform security assessments.",
      "from_domain": "Task Management Domain",
      "relation_type": "Service Call",
      "strength": 8.0,
      "to_domain": "Security Assessment Domain"
    },
    {
      "description": "Web interface displays reports generated by the reporting domain.",
      "from_domain": "Web Interface Domain",
      "relation_type": "Data Dependency",
      "strength": 6.0,
      "to_domain": "Reporting Domain"
    }
  ]
}
```

### Workflow Research Report
Contains static analysis results of the codebase and business process analysis.

```json
"```markdown\n# System Workflow Analysis\n\n## 1. Main Workflow\n- **Workflow Name**: Security Assessment Execution\n- **Description**: This workflow executes a comprehensive security assessment, which includes reconnaissance, scanning, and vulnerability assessment phases. It is designed to identify potential security vulnerabilities in a system by systematically analyzing various aspects of the target environment.\n- **Flow Diagram**:\n```mermaid\ngraph TD\n    A[Start Security Assessment] --> B[Reconnaissance Phase]\n    B --> C[Scanning Phase]\n    C --> D[Vulnerability Assessment Phase]\n    D --> E[Generate Report]\n    E --> F[End]\n```\n- **Key Steps**:\n  1. **Reconnaissance Phase**: Identify existing targets, resolve IPs, and perform basic web fingerprinting.\n  2. **Scanning Phase**: Conduct detailed scanning and enumeration of discovered web ports, including security header analysis and TLS inspection.\n  3. **Vulnerability Assessment Phase**: Run vulnerability assessments using detection engines like nuclei and sqlmap, confirming vulnerabilities with evidence-backed results.\n  4. **Generate Report**: Compile findings into a comprehensive report for review.\n\n## 2. Other Important Workflows\n\n### 2.1 AI-Enhanced Analysis\n- **Description**: This workflow integrates AI analysis into the security assessment process, leveraging external AI providers for advanced analysis.\n- **Flow Diagram**:\n```mermaid\ngraph TD\n    A[Start AI Analysis] --> B[Check AI Providers Availability]\n    B --> C[Perform AI-based Analysis]\n    C --> D[Integrate AI Results with Security Assessment]\n    D --> E[End]\n```\n\n### 2.2 Task Management and Execution\n- **Description**: Manages the distributed execution of tasks using Celery, ensuring scalable and efficient processing of security assessments.\n- **Flow Diagram**:\n```mermaid\ngraph TD\n    A[Initialize Task Management] --> B[Define Celery Tasks]\n    B --> C[Setup Celery Application]\n    C --> D[Execute Tasks]\n    D --> E[Collect Results]\n    E --> F[End]\n```\n\n## 3. Workflow Insights\n- **Key Observations**:\n  - The system is designed to provide automated and comprehensive security assessments, improving efficiency and accuracy.\n  - Integration with AI providers enhances the depth of analysis, offering advanced insights into potential vulnerabilities.\n  - The use of Celery for task management allows for scalable and distributed execution, which is crucial for handling large-scale assessments.\n\n- **Potential Optimization Opportunities**:\n  - Further integration with additional AI providers could enhance the analysis capabilities.\n  - Optimizing the task execution pipeline could reduce latency and improve throughput.\n\n- **Dependencies Between Workflows**:\n  - The Security Assessment Execution workflow relies on the AI-Enhanced Analysis workflow for advanced insights.\n  - The Task Management and Execution workflow underpins the entire assessment process, ensuring tasks are executed efficiently and results are collected systematically.\n```\nThis documentation provides a clear and structured overview of the main workflows within the Sentari system, aligning with the provided research materials and ensuring consistency with documented business processes."
```

### Code Insights Data
Code analysis results from preprocessing phase, including definitions of functions, classes, and modules.

```json
{
  "directory_insights": [
    {
      "file_count": 5,
      "file_insights": [
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file sets up the 'sentari' namespace and includes a secret configuration with sensitive data like database URLs and credentials. It is crucial for isolating resources and managing sensitive information securely.",
          "file_path": "/home/ahmad/Downloads/sentari/deploy/k8s/00-namespace-config.yaml",
          "importance_score": 0.9,
          "interfaces": [],
          "name": "00-namespace-config.yaml",
          "responsibilities": [
            "Define namespace",
            "Configure secrets",
            "Manage sensitive data",
            "Isolate application resources"
          ],
          "source_summary": "The file creates a namespace named 'sentari' and a secret named 'sentari-config' with database and broker connection details.",
          "summary": "Defines the namespace and a secret configuration for the 'sentari' application."
        },
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file specifies the deployment of a Redis instance using a single replica. It includes readiness probes to ensure the service is operational before accepting traffic.",
          "file_path": "/home/ahmad/Downloads/sentari/deploy/k8s/10-redis.yaml",
          "importance_score": 0.85,
          "interfaces": [],
          "name": "10-redis.yaml",
          "responsibilities": [
            "Deploy Redis instance",
            "Ensure service readiness",
            "Expose Redis port"
          ],
          "source_summary": "Defines a Redis deployment with one replica, readiness probes, and exposes port 6379.",
          "summary": "Configures a Redis deployment within the 'sentari' namespace."
        },
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file configures a PostgreSQL deployment with a persistent volume claim for data storage. It ensures data persistence and defines environment variables for database configuration.",
          "file_path": "/home/ahmad/Downloads/sentari/deploy/k8s/20-postgres.yaml",
          "importance_score": 0.9,
          "interfaces": [],
          "name": "20-postgres.yaml",
          "responsibilities": [
            "Deploy PostgreSQL instance",
            "Ensure data persistence",
            "Configure database environment"
          ],
          "source_summary": "Includes a persistent volume claim for 2Gi storage and a PostgreSQL deployment with environment variables.",
          "summary": "Sets up a PostgreSQL deployment and persistent volume claim."
        },
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file configures the deployment of two worker instances for processing tasks. It allows horizontal scaling by adjusting the number of replicas.",
          "file_path": "/home/ahmad/Downloads/sentari/deploy/k8s/30-worker.yaml",
          "importance_score": 0.8,
          "interfaces": [],
          "name": "30-worker.yaml",
          "responsibilities": [
            "Deploy worker instances",
            "Enable horizontal scaling",
            "Process application tasks"
          ],
          "source_summary": "Specifies a deployment with two replicas of the 'sentari-worker' using the latest image.",
          "summary": "Defines the deployment of worker instances for the 'sentari' application."
        },
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file sets up a single instance of the 'sentari-dashboard', providing a read-only interface to monitor the application. It binds to all interfaces within the pod.",
          "file_path": "/home/ahmad/Downloads/sentari/deploy/k8s/40-dashboard.yaml",
          "importance_score": 0.85,
          "interfaces": [],
          "name": "40-dashboard.yaml",
          "responsibilities": [
            "Deploy dashboard instance",
            "Provide monitoring interface",
            "Bind to pod interfaces"
          ],
          "source_summary": "Defines a deployment for the 'sentari-dashboard' with one replica and a command to serve the dashboard.",
          "summary": "Configures the deployment of the 'sentari' dashboard."
        }
      ],
      "importance_score": 0.9,
      "key_files": [
        "00-namespace-config.yaml",
        "10-redis.yaml",
        "20-postgres.yaml",
        "30-worker.yaml",
        "40-dashboard.yaml"
      ],
      "name": "k8s",
      "path": "/home/ahmad/Downloads/sentari/deploy/k8s",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'k8s' directory contains Kubernetes configuration files that define the infrastructure setup for a project named 'sentari'. It includes configurations for namespaces, secrets, deployments, and persistent volume claims, essential for deploying and managing the application's components like Redis, PostgreSQL, workers, and a dashboard."
    },
    {
      "file_count": 10,
      "file_insights": [
        {
          "code_purpose": "config",
          "dependencies": [],
          "detailed_description": "This file sets up the Sentari package, providing a version identifier for the package.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/__init__.py",
          "importance_score": 0.3,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Initialize package",
            "Provide version information"
          ],
          "source_summary": "Contains a docstring describing Sentari and sets the version to 0.1.0.",
          "summary": "Initializes the Sentari package with version information."
        },
        {
          "code_purpose": "entry",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./cli",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file serves as the main entry point for the Sentari command-line interface, invoking the main function from the CLI module.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/__main__.py",
          "importance_score": 0.95,
          "interfaces": [],
          "name": "__main__.py",
          "responsibilities": [
            "Execute CLI",
            "Handle system exit"
          ],
          "source_summary": "Imports the main function from the CLI module and executes it, raising a SystemExit.",
          "summary": "Main entry point for executing the Sentari CLI."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "ipaddress",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "json",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "socket",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "dataclasses",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "datetime",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "pathlib",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This module enforces scope-based authorization and maintains an audit log of operations, ensuring that all actions are authorized and logged.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/authorization.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "AuthorizationError",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Scope",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "from_items",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "items",
                  "param_type": "list[str]"
                }
              ],
              "return_type": "Scope",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "contains",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                }
              ],
              "return_type": "bool",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "is_empty",
              "parameters": [],
              "return_type": "bool",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "host_only",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "AuditLog",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "authorize",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "scope",
                  "param_type": "Scope"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "authorized",
                  "param_type": "bool"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "audit",
                  "param_type": "AuditLog"
                }
              ],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "authorization.py",
          "responsibilities": [
            "Enforce authorization",
            "Manage scopes",
            "Log audits",
            "Resolve hostnames"
          ],
          "source_summary": "Defines classes and functions for authorization, including scope management and audit logging.",
          "summary": "Handles authorization and audit logging for Sentari."
        },
        {
          "code_purpose": "command",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "argparse",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "json",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "sys",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "pathlib",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./authorization",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./phases",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./reporting",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file defines the command-line interface for Sentari, including argument parsing and execution of security assessment phases.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/cli.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "build_parser",
              "parameters": [],
              "return_type": "argparse.ArgumentParser",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "main",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "argv",
                  "param_type": "list[str] | None"
                }
              ],
              "return_type": "int",
              "visibility": ""
            }
          ],
          "name": "cli.py",
          "responsibilities": [
            "Parse CLI arguments",
            "Execute main logic",
            "Print analysis results"
          ],
          "source_summary": "Defines functions for building the CLI parser, printing analysis, and executing the main CLI logic.",
          "summary": "Implements the command-line interface for Sentari."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "dataclasses",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "typing",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./models",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This module tags findings with compliance standards references, providing context to the results produced by Sentari.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/compliance.py",
          "importance_score": 0.7,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "ComplianceTags",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "as_dict",
              "parameters": [],
              "return_type": "dict",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "label",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "map_finding",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "f",
                  "param_type": "Finding"
                }
              ],
              "return_type": "Optional[ComplianceTags]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "apply",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                }
              ],
              "return_type": "dict[str, int]",
              "visibility": ""
            }
          ],
          "name": "compliance.py",
          "responsibilities": [
            "Map findings to standards",
            "Provide compliance context",
            "Apply compliance rules"
          ],
          "source_summary": "Defines classes and functions for compliance tagging and mapping findings to standards.",
          "summary": "Maps findings to compliance standards."
        },
        {
          "code_purpose": "util",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "concurrent.futures",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "typing",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This utility module implements lightweight parallelism using thread pools to speed up network probes by running them concurrently.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/concurrency.py",
          "importance_score": 0.5,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "pmap",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "fn",
                  "param_type": "Callable[[T], R]"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "items",
                  "param_type": "Iterable[T]"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "workers",
                  "param_type": "int"
                }
              ],
              "return_type": "list[R]",
              "visibility": ""
            }
          ],
          "name": "concurrency.py",
          "responsibilities": [
            "Enable parallel execution",
            "Optimize network probes"
          ],
          "source_summary": "Defines a function for parallel mapping using a thread pool executor.",
          "summary": "Provides lightweight parallelism for network probes."
        },
        {
          "code_purpose": "service",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "pathlib",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "typing",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./authorization",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./models",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./phases",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./runner",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file contains the core logic for executing the assessment phases, ensuring consistent behavior whether run locally or distributed.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/engine.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "payload_from_results",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "analysis_dict",
                  "param_type": "Optional[dict]"
                }
              ],
              "return_type": "dict",
              "visibility": ""
            }
          ],
          "name": "engine.py",
          "responsibilities": [
            "Execute assessment phases",
            "Generate result payloads"
          ],
          "source_summary": "Defines functions for running assessments and generating payloads from results.",
          "summary": "Runs the assessment phases for Sentari."
        },
        {
          "code_purpose": "model",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "uuid",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "dataclasses",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "datetime",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "enum",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This module provides the core data models used throughout Sentari, ensuring that findings are backed by evidence and maintaining the integrity of the assessment results.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/models.py",
          "importance_score": 0.8,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_now",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Severity",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "rank",
              "parameters": [],
              "return_type": "int",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Evidence",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "summary",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Finding",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "PhaseResult",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "to_dict",
              "parameters": [],
              "return_type": "dict[str, Any]",
              "visibility": ""
            }
          ],
          "name": "models.py",
          "responsibilities": [
            "Define data models",
            "Ensure evidence-backed findings",
            "Manage phase results"
          ],
          "source_summary": "Defines classes and functions for managing findings, evidence, and phase results.",
          "summary": "Defines core data models for Sentari."
        },
        {
          "code_purpose": "specificfeature",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./models",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This module provides functionality to compare current scan results against a baseline, identifying fixed, still-present, and new issues.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/retest.py",
          "importance_score": 0.75,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_sig_finding",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "f",
                  "param_type": "Finding"
                }
              ],
              "return_type": "tuple[str, str, str]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "RetestResult",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "findings_from_payload",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "data",
                  "param_type": "Any"
                }
              ],
              "return_type": "list[dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "load_baseline",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "path",
                  "param_type": "str"
                }
              ],
              "return_type": "list[dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "compare",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "baseline",
                  "param_type": "list[dict]"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "current",
                  "param_type": "list[Finding]"
                }
              ],
              "return_type": "RetestResult",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "render",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "rr",
                  "param_type": "RetestResult"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "baseline_path",
                  "param_type": "str"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "to_dict",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "rr",
                  "param_type": "RetestResult"
                }
              ],
              "return_type": "dict",
              "visibility": ""
            }
          ],
          "name": "retest.py",
          "responsibilities": [
            "Compare scan results",
            "Identify issue status",
            "Load baseline data"
          ],
          "source_summary": "Defines functions and classes for retesting and comparing scan results with a baseline.",
          "summary": "Compares current scan results with a baseline."
        },
        {
          "code_purpose": "tool",
          "dependencies": [
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "shutil",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "subprocess",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "time",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "uuid",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "datetime",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "./models",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This module is responsible for running external tools, capturing their output as evidence, and ensuring that findings are based on real data.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/runner.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "ToolRunner",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "__init__",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "default_timeout",
                  "param_type": "int"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "dry_run",
                  "param_type": "bool"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "available",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "tool",
                  "param_type": "str"
                }
              ],
              "return_type": "bool",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "evidence",
              "parameters": [],
              "return_type": "list[Evidence]",
              "visibility": ""
            }
          ],
          "name": "runner.py",
          "responsibilities": [
            "Run external tools",
            "Capture tool output",
            "Manage evidence"
          ],
          "source_summary": "Defines the ToolRunner class for executing tools and managing evidence.",
          "summary": "Executes external tools and records evidence."
        }
      ],
      "importance_score": 0.9,
      "key_files": [
        "__main__.py",
        "authorization.py",
        "cli.py",
        "engine.py",
        "runner.py"
      ],
      "name": "sentari",
      "path": "/home/ahmad/Downloads/sentari/sentari",
      "purpose": "other",
      "subdirectory_count": 7,
      "summary": "The 'sentari' directory is a core component of the Sentari security assessment tool, providing functionalities for authorization, compliance, concurrency, and assessment execution. It integrates various modules to ensure evidence-grounded security assessments, with a focus on authorization and compliance mapping."
    },
    {
      "file_count": 3,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/ai/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file sets up the AI module by importing and exporting essential classes and functions from the 'providers' and 'analyst' modules. It defines the public API of the AI package.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/ai/__init__.py",
          "importance_score": 0.7,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Define module exports",
            "Import key components"
          ],
          "source_summary": "Imports key classes and functions from 'providers' and 'analyst' and defines the '__all__' list for module exports.",
          "summary": "Initializes the AI module by exporting key classes and functions."
        },
        {
          "code_purpose": "service",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/ai/analyst.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file provides classes and functions for conducting AI-based analysis. It includes the 'GroundedAnalyst' class for performing analysis and the 'Analysis' class for representing analysis results.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/ai/analyst.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "Analysis",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_findings_payload",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                }
              ],
              "return_type": "tuple[list[dict], set[str]]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "GroundedAnalyst",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "__init__",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "provider",
                  "param_type": "LLMProvider"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "analyze",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                }
              ],
              "return_type": "Analysis",
              "visibility": ""
            }
          ],
          "name": "analyst.py",
          "responsibilities": [
            "Perform AI analysis",
            "Represent analysis results",
            "Extract JSON data"
          ],
          "source_summary": "Defines 'GroundedAnalyst' and 'Analysis' classes, and functions for analyzing results and extracting JSON data.",
          "summary": "Implements grounded AI analysis functionalities."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/ai/providers.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file abstracts various AI providers, such as OpenAI and Google, under a unified interface. It includes classes for each provider and methods to check availability and perform completions.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/ai/providers.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_try_import",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "mod",
                  "param_type": "str"
                }
              ],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "LLMProvider",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "available",
              "parameters": [],
              "return_type": "tuple[bool, str]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "complete",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "system",
                  "param_type": "str"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "user",
                  "param_type": "str"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "max_tokens",
                  "param_type": "int"
                }
              ],
              "return_type": "str",
              "visibility": ""
            }
          ],
          "name": "providers.py",
          "responsibilities": [
            "Abstract AI providers",
            "Check provider availability",
            "Perform text completions"
          ],
          "source_summary": "Defines classes for different AI providers and methods to check their availability and perform text completions.",
          "summary": "Manages multiple AI providers and abstracts their interfaces."
        }
      ],
      "importance_score": 0.9,
      "key_files": [
        "providers.py",
        "analyst.py",
        "__init__.py"
      ],
      "name": "ai",
      "path": "/home/ahmad/Downloads/sentari/sentari/ai",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'ai' directory serves as a core component of the application, providing AI-related functionalities. It includes modules for managing AI providers, conducting analysis, and initializing exports. The files work together to abstract multiple AI providers and perform grounded analysis using AI models."
    },
    {
      "file_count": 2,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/db/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file serves as the initializer for the 'db' module, making the RunStore class available for import when the module is imported. It sets up the module's public interface.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/db/__init__.py",
          "importance_score": 0.6,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Initialize the db module",
            "Expose RunStore class"
          ],
          "source_summary": "The file imports the RunStore class from the store module and includes it in the module's public API using __all__.",
          "summary": "Initializes the database module by exposing the RunStore class."
        },
        {
          "code_purpose": "dao",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/db/store.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "importlib",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "json",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "sqlite3",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "uuid",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "datetime",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": true,
              "line_number": null,
              "name": "timezone",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "The store.py file defines the RunStore class, which provides methods for saving, retrieving, and managing run data in a database. It supports both SQLite and Postgres backends, ensuring data portability and flexibility.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/db/store.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_now",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_summarize",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "payload",
                  "param_type": "dict"
                }
              ],
              "return_type": "tuple[int, dict[str, int]]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "RunStore",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "__init__",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "dsn",
                  "param_type": "str"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "_init",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "save_run",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "payload",
                  "param_type": "dict"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "all_runs",
              "parameters": [],
              "return_type": "dict[str, dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "get_run",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "rid",
                  "param_type": "str"
                }
              ],
              "return_type": "Optional[dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "latest_for_target",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                }
              ],
              "return_type": "Optional[dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "close",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "store.py",
          "responsibilities": [
            "Initialize database connection",
            "Save run data",
            "Retrieve all runs",
            "Get specific run data",
            "Close database connection"
          ],
          "source_summary": "The file includes the RunStore class with methods for initializing the database, saving runs, retrieving all runs, getting specific runs, and closing the database connection. It uses SQLite by default but can switch to Postgres if configured.",
          "summary": "Implements the RunStore class for managing run data persistence."
        }
      ],
      "importance_score": 0.85,
      "key_files": [
        "store.py",
        "__init__.py"
      ],
      "name": "db",
      "path": "/home/ahmad/Downloads/sentari/sentari/db",
      "purpose": "database",
      "subdirectory_count": 0,
      "summary": "The 'db' directory is responsible for managing the persistence layer of the application, specifically handling the storage and retrieval of run data. It includes a module for defining the data access object and a class for interacting with the database, supporting both SQLite and Postgres backends."
    },
    {
      "file_count": 2,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/parsers/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file sets up the module's public interface by importing key functions and classes from 'nmap.py'. It ensures that 'parse_nmap_xml' and 'ServiceRecord' are accessible when the module is imported.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/parsers/__init__.py",
          "importance_score": 0.4,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Define module exports",
            "Facilitate module imports"
          ],
          "source_summary": "Imports 'parse_nmap_xml' and 'ServiceRecord' from 'nmap.py' and includes them in '__all__' for public access.",
          "summary": "Initializes the parsers module by defining its public interface."
        },
        {
          "code_purpose": "tool",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/parsers/nmap.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/parsers/nmap.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/parsers/nmap.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/parsers/nmap.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file contains the logic to parse nmap XML output, converting it into structured data using the 'ServiceRecord' class. It includes functions to handle XML parsing and data extraction, providing a clear interface for other parts of the application to use.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/parsers/nmap.py",
          "importance_score": 0.8,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "ServiceRecord",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "label",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "method",
              "name": "label",
              "parameters": [],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "parse_nmap_xml",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "xml_text",
                  "param_type": "str"
                }
              ],
              "return_type": "list[ServiceRecord]",
              "visibility": ""
            }
          ],
          "name": "nmap.py",
          "responsibilities": [
            "Parse nmap XML output",
            "Define data structure for service records",
            "Provide parsing interface"
          ],
          "source_summary": "Defines 'ServiceRecord' class and 'parse_nmap_xml' function to parse XML data. Utilizes Python's 'xml.etree.ElementTree' for XML parsing and 'dataclasses' for data structure definition.",
          "summary": "Parses nmap XML output into structured service records."
        }
      ],
      "importance_score": 0.7,
      "key_files": [
        "nmap.py",
        "__init__.py"
      ],
      "name": "parsers",
      "path": "/home/ahmad/Downloads/sentari/sentari/parsers",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'parsers' directory is responsible for parsing nmap XML output into structured data. It contains two files: '__init__.py' which sets up the module exports, and 'nmap.py' which implements the parsing logic and defines the data structure for service records."
    },
    {
      "file_count": 6,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/phases/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file serves as the entry point for the 'phases' module, importing and registering all the phase classes that are implemented in the directory. It defines the order in which phases are executed.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/phases/__init__.py",
          "importance_score": 0.8,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Import phase classes",
            "Register phases",
            "Define execution order"
          ],
          "source_summary": "Imports phase classes and registers them in a list to define execution order.",
          "summary": "Initializes the phase registry and imports phase classes."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/phases/base.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file provides the foundational classes and methods for defining phases. It includes abstract classes and methods that other phase implementations extend and implement.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/phases/base.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "class",
              "name": "PhaseContext",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Phase",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "execute",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "result",
                  "param_type": "PhaseResult"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "run",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                }
              ],
              "return_type": "PhaseResult",
              "visibility": ""
            }
          ],
          "name": "base.py",
          "responsibilities": [
            "Define PhaseContext class",
            "Define Phase class",
            "Provide abstract methods for execution"
          ],
          "source_summary": "Defines abstract classes and methods for phase execution and context handling.",
          "summary": "Defines the base framework for phases."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/phases/recon.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file implements the reconnaissance phase, which aims to identify existing targets, resolve IPs, and perform basic web fingerprinting. It uses built-in tools and optionally integrates with external tools like nmap.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/phases/recon.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_hostname",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "ReconPhase",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "execute",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "result",
                  "param_type": "PhaseResult"
                }
              ],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "recon.py",
          "responsibilities": [
            "Resolve hostnames",
            "Perform port scanning",
            "Conduct web fingerprinting"
          ],
          "source_summary": "Defines functions for hostname resolution, port scanning, and web fingerprinting.",
          "summary": "Implements the reconnaissance phase."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/phases/scanning.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file builds on the reconnaissance phase by performing detailed scanning and enumeration of discovered web ports. It includes security header analysis, TLS inspection, and content discovery.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/phases/scanning.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_web_targets",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                }
              ],
              "return_type": "list[tuple[str, int]]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "ScanPhase",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "execute",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "result",
                  "param_type": "PhaseResult"
                }
              ],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "scanning.py",
          "responsibilities": [
            "Identify web targets",
            "Analyze security headers",
            "Inspect TLS configurations"
          ],
          "source_summary": "Defines functions for web target identification, security header analysis, and TLS checks.",
          "summary": "Implements the scanning and enumeration phase."
        },
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/phases/vuln.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file runs vulnerability assessments using detection engines like nuclei and sqlmap. It focuses on confirming vulnerabilities with evidence-backed results.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/phases/vuln.py",
          "importance_score": 0.85,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_urls",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                }
              ],
              "return_type": "list[str]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "VulnPhase",
              "parameters": [],
              "return_type": null,
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "execute",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctx",
                  "param_type": "PhaseContext"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "result",
                  "param_type": "PhaseResult"
                }
              ],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "vuln.py",
          "responsibilities": [
            "Extract URLs for testing",
            "Run nuclei for detection",
            "Execute sqlmap for SQL injection testing"
          ],
          "source_summary": "Defines functions for URL extraction and running vulnerability detection tools.",
          "summary": "Implements the vulnerability assessment phase."
        }
      ],
      "importance_score": 0.9,
      "key_files": [
        "__init__.py",
        "base.py",
        "recon.py",
        "scanning.py",
        "vuln.py"
      ],
      "name": "phases",
      "path": "/home/ahmad/Downloads/sentari/sentari/phases",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'phases' directory is a core component of the application, responsible for defining and executing various phases of a process, such as reconnaissance, scanning, vulnerability assessment, and verification. Each file in the directory represents a specific phase, implementing the logic and tools necessary to perform its tasks."
    },
    {
      "file_count": 3,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file sets up the reporting package by importing and exposing the 'console' and 'html' modules. It ensures that these modules can be accessed when the reporting package is imported.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/reporting/__init__.py",
          "importance_score": 0.4,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Initialize reporting package",
            "Expose console and html modules"
          ],
          "source_summary": "The file imports 'console' and 'html' modules and defines '__all__' to specify the public API of the package.",
          "summary": "Initializes the reporting module by exposing key submodules."
        },
        {
          "code_purpose": "specificfeature",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/console.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/console.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file provides functionality to render reports in a console-friendly format. It organizes findings by severity and ensures that each finding is linked to its evidence, making the report auditable.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/reporting/console.py",
          "importance_score": 0.7,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "render",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                }
              ],
              "return_type": "str",
              "visibility": ""
            }
          ],
          "name": "console.py",
          "responsibilities": [
            "Render console reports",
            "Order findings by severity",
            "Label findings with severity",
            "Ensure auditability of reports"
          ],
          "source_summary": "Defines a 'render' function that takes a list of 'PhaseResult' objects and returns a formatted string for console output. It uses severity levels to order and label findings.",
          "summary": "Generates human-readable console reports."
        },
        {
          "code_purpose": "specificfeature",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/html.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/html.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/html.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/reporting/html.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file is responsible for creating HTML reports that are self-contained and do not require external assets. It uses HTML details elements to ensure that findings are linked to their evidence, maintaining the auditability of the report.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/reporting/html.py",
          "importance_score": 0.8,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_esc",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "s",
                  "param_type": "object"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "render_html",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "results",
                  "param_type": "list[PhaseResult]"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "target",
                  "param_type": "str"
                }
              ],
              "return_type": "str",
              "visibility": ""
            }
          ],
          "name": "html.py",
          "responsibilities": [
            "Render HTML reports",
            "Escape HTML content",
            "Color-code findings by severity",
            "Ensure auditability of reports"
          ],
          "source_summary": "Defines '_esc' and 'render_html' functions to escape HTML content and render a list of 'PhaseResult' objects into an HTML string. It uses severity levels to color-code findings.",
          "summary": "Generates self-contained HTML reports."
        }
      ],
      "importance_score": 0.75,
      "key_files": [
        "console.py",
        "html.py"
      ],
      "name": "reporting",
      "path": "/home/ahmad/Downloads/sentari/sentari/reporting",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'reporting' directory is responsible for generating reports in both console and HTML formats. It includes modules that handle the rendering of human-readable and self-contained reports, ensuring that findings are auditable against raw data. The directory is crucial for presenting analysis results in a structured manner."
    },
    {
      "file_count": 3,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/__init__.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file initializes the tasks module by importing key components from other files and defining the module's public API. It ensures that the necessary components are available for external use.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/tasks/__init__.py",
          "importance_score": 0.6,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Initialize the tasks module",
            "Define public API for the module"
          ],
          "source_summary": "Imports components from 'app' and 'tasks' and defines the module's public API using '__all__'.",
          "summary": "Initializes the tasks module and defines exports."
        },
        {
          "code_purpose": "config",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/app.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/app.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/app.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file sets up an optional Celery application for distributed task execution. It checks for the presence of Celery and a broker, and configures the application accordingly. It provides a function to create the application if the necessary components are available.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/tasks/app.py",
          "importance_score": 0.8,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "make_app",
              "parameters": [],
              "return_type": "void",
              "visibility": ""
            }
          ],
          "name": "app.py",
          "responsibilities": [
            "Setup Celery application",
            "Check for Celery and broker availability",
            "Configure application settings"
          ],
          "source_summary": "Defines a Celery application setup with lazy imports and configuration based on environment variables.",
          "summary": "Handles optional Celery application setup for distributed task execution."
        },
        {
          "code_purpose": "service",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file defines Celery tasks that wrap the shared assessment engine, allowing for distributed execution of assessments. It ensures that tasks dispatched to workers behave identically to local executions and supports persistence of results when a database is configured.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/tasks/tasks.py",
          "importance_score": 0.9,
          "interfaces": [],
          "name": "tasks.py",
          "responsibilities": [
            "Define Celery tasks",
            "Wrap assessment engine",
            "Support distributed task execution",
            "Persist results if configured"
          ],
          "source_summary": "Defines a Celery task that wraps the assessment engine, enabling distributed execution and optional result persistence.",
          "summary": "Defines Celery tasks for running assessments."
        }
      ],
      "importance_score": 0.85,
      "key_files": [
        "app.py",
        "tasks.py",
        "__init__.py"
      ],
      "name": "tasks",
      "path": "/home/ahmad/Downloads/sentari/sentari/tasks",
      "purpose": "other",
      "subdirectory_count": 0,
      "summary": "The 'tasks' directory is responsible for managing task execution, particularly using Celery for distributed task handling. It includes initialization, application setup, and task definition files that work together to facilitate task management and execution within the system."
    },
    {
      "file_count": 2,
      "file_insights": [
        {
          "code_purpose": "module",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/web/__init__.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "This file serves as the entry point for the 'web' module, making the 'serve' function available for import. It is minimal in content, primarily focusing on module initialization.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/web/__init__.py",
          "importance_score": 0.4,
          "interfaces": [],
          "name": "__init__.py",
          "responsibilities": [
            "Initialize the web module",
            "Expose the 'serve' function"
          ],
          "source_summary": "The file imports the 'serve' function from the 'server' module and includes it in the '__all__' list for public API exposure.",
          "summary": "Initializes the web module by exposing the 'serve' function."
        },
        {
          "code_purpose": "service",
          "dependencies": [
            {
              "dependency_type": "from_import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/web/server.py",
              "path": null,
              "version": null
            },
            {
              "dependency_type": "import",
              "is_external": false,
              "line_number": null,
              "name": "/home/ahmad/Downloads/sentari/sentari/web/server.py",
              "path": null,
              "version": null
            }
          ],
          "detailed_description": "The 'server.py' file is the core of the web module, providing functionality to serve a web dashboard and REST API. It handles HTTP GET requests to display a list of runs and detailed views of individual runs, ensuring the service remains read-only.",
          "file_path": "/home/ahmad/Downloads/sentari/sentari/web/server.py",
          "importance_score": 0.9,
          "interfaces": [
            {
              "description": null,
              "interface_type": "function",
              "name": "_esc",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "s",
                  "param_type": "Any"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_load_runs",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "runs_dir",
                  "param_type": "Path"
                }
              ],
              "return_type": "dict[str, dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_findings",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "run",
                  "param_type": "dict"
                }
              ],
              "return_type": "list[dict]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_counts",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "findings",
                  "param_type": "list[dict]"
                }
              ],
              "return_type": "dict[str, int]",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_dashboard",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "runs",
                  "param_type": "dict[str, dict]"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_run_view",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "rid",
                  "param_type": "str"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "run",
                  "param_type": "dict"
                }
              ],
              "return_type": "str",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "make_handler",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "load",
                  "param_type": "Any"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "class",
              "name": "Handler",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "log_message",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "a",
                  "param_type": "tuple"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "_send",
              "parameters": [
                {
                  "description": null,
                  "is_optional": false,
                  "name": "code",
                  "param_type": "Any"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "body",
                  "param_type": "Any"
                },
                {
                  "description": null,
                  "is_optional": false,
                  "name": "ctype",
                  "param_type": "Any"
                }
              ],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "do_GET",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            },
            {
              "description": null,
              "interface_type": "function",
              "name": "load",
              "parameters": [],
              "return_type": "None",
              "visibility": ""
            }
          ],
          "name": "server.py",
          "responsibilities": [
            "Serve a web dashboard",
            "Handle HTTP GET requests",
            "Parse and display run data",
            "Ensure read-only access",
            "Generate HTML views"
          ],
          "source_summary": "The file defines multiple functions and a class to handle HTTP requests, parse run data, and generate HTML views. It includes a handler class and several utility functions for data processing.",
          "summary": "Implements a read-only web dashboard and REST API for viewing assessment runs."
        }
      ],
      "importance_score": 0.85,
      "key_files": [
        "server.py",
        "__init__.py"
      ],
      "name": "web",
      "path": "/home/ahmad/Downloads/sentari/sentari/web",
      "purpose": "frontend",
      "subdirectory_count": 0,
      "summary": "The 'web' directory serves as a backend component providing a read-only web dashboard and REST API for viewing completed assessments. It includes an initialization file and a server file that handles HTTP requests and serves data from saved runs."
    }
  ],
  "file_insights": []
}
```

## Memory Storage Statistics

**Total Storage Size**: 141411 bytes

- **studies_research**: 28269 bytes (20.0%)
- **documentation**: 43485 bytes (30.8%)
- **timing**: 32 bytes (0.0%)
- **preprocess**: 69625 bytes (49.2%)

## Generated Documents Statistics

Number of Generated Documents: 10

- Key Modules and Components Research Report_Security Assessment Domain
- Boundary Interfaces
- Core Workflows
- Key Modules and Components Research Report_Task Management Domain
- Project Overview
- Key Modules and Components Research Report_AI Integration Domain
- Architecture Description
- Key Modules and Components Research Report_Reporting Domain
- Key Modules and Components Research Report_Web Interface Domain
- Database Overview
