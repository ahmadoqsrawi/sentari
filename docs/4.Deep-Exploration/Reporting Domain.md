# Reporting Domain Documentation

## Overview

The Reporting Domain in the Sentari system is responsible for generating comprehensive reports from security assessments. This domain focuses on transforming raw assessment data into structured, self-contained HTML reports that are easy to review and audit. The reports are designed to be standalone, requiring no external assets or JavaScript, ensuring they are portable and secure.

## Module Description

### HTML Reporting Module

- **Purpose**: The HTML Reporting module generates detailed HTML reports from security assessment results. These reports are self-contained, meaning they do not rely on external resources, which enhances their portability and security.
- **Key Functions**:
  - **_esc**: Escapes HTML content to prevent injection attacks and ensure the integrity of the report.
  - **render_html**: Converts a list of `PhaseResult` objects into an HTML string, organizing findings by severity and providing detailed evidence for each finding.

## Technical Implementation

### Key Components

1. **Severity Levels**: The module uses predefined severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) to categorize findings. Each level is associated with a specific color code for visual differentiation in the report.

2. **HTML Escaping**: The `_esc` function is utilized to escape HTML content, ensuring that any dynamic content included in the report does not introduce security vulnerabilities.

3. **HTML Rendering**: The `render_html` function is the core of the module, responsible for:
   - Aggregating findings and evidence from `PhaseResult` objects.
   - Generating HTML tiles that summarize the number of findings per severity level.
   - Creating detailed sections for each finding, including evidence links, descriptions, recommendations, and compliance tags.
   - Compiling all evidence into an appendix for easy reference.

### Interaction with Other Components

- **PhaseResult Objects**: The module interacts with `PhaseResult` objects, which contain the findings and evidence collected during security assessments. These objects are processed to extract relevant information for the report.
- **Severity and Evidence**: The module uses severity levels to organize findings and evidence, ensuring that the most critical issues are highlighted prominently.

## Practical Usage

The HTML Reporting module is designed to be integrated into the Sentari security assessment workflow, where it is invoked after the assessment phases are completed. The generated reports provide a comprehensive overview of the assessment results, making it easier for security analysts to review findings and take appropriate actions.

## Conclusion

The Reporting Domain, specifically the HTML Reporting module, plays a crucial role in the Sentari system by transforming complex security assessment data into clear, actionable reports. Its design emphasizes security, portability, and ease of use, aligning with the overall goals of the Sentari architecture to provide automated and comprehensive security assessments.