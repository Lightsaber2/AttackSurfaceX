"""
pdf_generator.py

Generates professional PDF reports from scan results.
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, 
    Spacer, PageBreak, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from utils import app_logger


class PDFReportGenerator:
    """
    Generates professional PDF reports from scan data.
    """
    
    def __init__(self):
        self.logger = app_logger
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495E'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Risk header style
        self.styles.add(ParagraphStyle(
            name='RiskHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#E74C3C'),
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
    
    def generate(self, report_data: Dict[str, Any], output_path: str) -> bool:
        """
        Generate a PDF report from scan data.
        
        Args:
            report_data: Dictionary containing scan results
            output_path: Path where PDF should be saved
        
        Returns:
            True if successful, False otherwise
        """
        try:
            self.logger.info(f"Generating PDF report: {output_path}")
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=1*inch,
                bottomMargin=0.75*inch,
            )
            
            # Build content
            story = []
            
            # Title page
            story.extend(self._build_title_page(report_data))
            
            # Executive summary
            story.extend(self._build_summary(report_data))
            
            # Risk assessment section
            story.extend(self._build_risk_assessment(report_data))
            
            # Changes section
            story.extend(self._build_changes_section(report_data))
            
            # Detailed findings
            story.extend(self._build_detailed_findings(report_data))
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"PDF report generated successfully: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {e}", exc_info=True)
            return False
    
    def _build_title_page(self, data: Dict) -> List:
        """Build the title page."""
        elements = []
        
        # Title
        title = Paragraph("AttackSurfaceX<br/>Security Scan Report", 
                         self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Scan information table
        scan_info = [
            ['Scan ID:', str(data['scan_id'])],
            ['Target:', data['target']],
            ['Profile:', data['profile'].upper()],
            ['Timestamp:', datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Duration:', f"{data.get('duration_seconds', 0):.2f} seconds"],
        ]
        
        info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 11),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2C3E50')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#ECF0F1')]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#BDC3C7')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
        ]))
        
        elements.append(info_table)
        elements.append(PageBreak())
        
        return elements
    
    def _build_summary(self, data: Dict) -> List:
        """Build executive summary section."""
        elements = []
        summary = data.get('summary', {})
        
        # Section title
        title = Paragraph("Executive Summary", self.styles['CustomSubtitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary statistics
        stats = [
            ['Metric', 'Value'],
            ['Total Events', str(summary.get('total_events', 0))],
            ['Open Ports', str(summary.get('open_ports', 0))],
            ['Closed Ports', str(summary.get('closed_ports', 0))],
            ['Filtered Ports', str(summary.get('filtered_ports', 0))],
            ['High Risk Findings', str(summary.get('high_risk_findings', 0))],
            ['Medium Risk Findings', str(summary.get('medium_risk_findings', 0))],
        ]
        
        stats_table = Table(stats, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 12),
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 11),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ECF0F1')]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#2C3E50')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_risk_assessment(self, data: Dict) -> List:
        """Build risk assessment section."""
        elements = []
        risks = data.get('risk_assessment', [])
        
        # Section title
        title = Paragraph("Risk Assessment", self.styles['CustomSubtitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        if not risks:
            no_risk = Paragraph("No risky services detected.", self.styles['Normal'])
            elements.append(no_risk)
            elements.append(Spacer(1, 0.3*inch))
            return elements
        
        # Sort by risk (highest first)
        sorted_risks = sorted(risks, key=lambda x: x['risk'], reverse=True)
        
        # Build risk table
        risk_data = [['Host', 'Port', 'Service', 'Risk Level']]
        
        for risk in sorted_risks:
            risk_level = f"{risk['risk']}/10"
            risk_data.append([
                risk['host'],
                str(risk['port']),
                risk.get('service', 'unknown'),
                risk_level
            ])
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch, 1.5*inch, 1.5*inch])
        
        # Define table style
        table_style = [
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 11),
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#2C3E50')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#BDC3C7')),
        ]
        
        # Color code risks
        for i, risk in enumerate(sorted_risks, start=1):
            if risk['risk'] >= 8:
                # High risk - red
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#FADBD8')))
            elif risk['risk'] >= 5:
                # Medium risk - yellow
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#FCF3CF')))
            else:
                # Low risk - green
                table_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor('#D5F4E6')))
        
        risk_table.setStyle(TableStyle(table_style))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_changes_section(self, data: Dict) -> List:
        """Build changes section."""
        elements = []
        changes = data.get('changes', {})
        
        # Section title
        title = Paragraph("Attack Surface Changes", self.styles['CustomSubtitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        opened = changes.get('opened_ports', [])
        closed = changes.get('closed_ports', [])
        
        if not opened and not closed:
            no_changes = Paragraph("No changes detected since last scan.", 
                                  self.styles['Normal'])
            elements.append(no_changes)
            elements.append(Spacer(1, 0.3*inch))
            return elements
        
        # Newly opened ports
        if opened:
            opened_title = Paragraph("Newly Opened Ports:", 
                                    self.styles['RiskHeader'])
            elements.append(opened_title)
            
            for host, port in opened:
                port_text = Paragraph(f"• {host}:{port}", self.styles['Normal'])
                elements.append(port_text)
            
            elements.append(Spacer(1, 0.2*inch))
        
        # Recently closed ports
        if closed:
            closed_title = Paragraph("Recently Closed Ports:", 
                                    self.styles['Normal'])
            elements.append(closed_title)
            
            for host, port in closed:
                port_text = Paragraph(f"• {host}:{port}", self.styles['Normal'])
                elements.append(port_text)
            
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_detailed_findings(self, data: Dict) -> List:
        """Build detailed findings section."""
        elements = []
        
        # Section title
        title = Paragraph("Detailed Findings", self.styles['CustomSubtitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        recommendations = [
            "• Review and justify all high-risk services (FTP, Telnet, PPTP)",
            "• Ensure all services are running latest patched versions",
            "• Implement firewall rules to restrict access to sensitive ports",
            "• Consider disabling unused services to reduce attack surface",
            "• Enable encryption for all remote access services",
            "• Implement network segmentation where applicable",
            "• Schedule regular security scans to track changes",
        ]
        
        rec_title = Paragraph("Security Recommendations:", 
                             self.styles['Heading3'])
        elements.append(rec_title)
        
        for rec in recommendations:
            rec_para = Paragraph(rec, self.styles['Normal'])
            elements.append(rec_para)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer = Paragraph(
            f"<i>Report generated by AttackSurfaceX on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>",
            self.styles['Normal']
        )
        elements.append(footer)
        
        return elements