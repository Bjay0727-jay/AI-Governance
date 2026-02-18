/**
 * ForgeAI Govern™ - Knowledge Base Handlers
 *
 * Static regulatory and framework documentation for healthcare AI governance.
 */

import { jsonResponse } from '../utils.js';

const ARTICLES = [
  {
    id: 'kb-nist-ai-rmf', category: 'framework', title: 'NIST AI Risk Management Framework (AI RMF)',
    summary: 'The NIST AI RMF provides a structured approach to managing AI risks through four core functions: Govern, Map, Measure, and Manage.',
    content: 'The NIST AI RMF 1.0 establishes a voluntary framework for managing risks associated with AI systems throughout their lifecycle. It defines four core functions:\n\n**Govern** - Establish and maintain organizational AI governance structures, policies, and processes.\n**Map** - Categorize AI systems, identify stakeholders, and understand the context of AI deployment.\n**Measure** - Assess and monitor AI risks including performance, bias, security, and compliance.\n**Manage** - Implement risk mitigation strategies, monitor controls, and respond to incidents.\n\nForgeAI Govern maps 39 controls across these four families.',
    frameworks: ['NIST AI RMF 1.0'], relevance: 'core',
  },
  {
    id: 'kb-fda-samd', category: 'regulatory', title: 'FDA Software as Medical Device (SaMD) Classification',
    summary: 'FDA regulates AI/ML-based Software as a Medical Device through pre-market pathways including 510(k), De Novo, and PMA.',
    content: 'The FDA classifies AI/ML-enabled medical devices based on the significance of the information provided by the SaMD to the healthcare decision and the state of the healthcare situation or condition. Key pathways:\n\n**510(k)** - Demonstrates substantial equivalence to a predicate device. Most common pathway for moderate-risk AI tools.\n**De Novo** - For novel, low-to-moderate risk devices without a predicate. Increasingly used for AI-based diagnostic tools.\n**PMA** - Pre-Market Approval required for high-risk (Class III) devices.\n\nThe FDA Action Plan for AI/ML-Based SaMD introduces the concept of Predetermined Change Control Plans (PCCPs) to accommodate iterative model updates.',
    frameworks: ['FDA SaMD', '21 CFR Part 820'], relevance: 'core',
  },
  {
    id: 'kb-hipaa-ai', category: 'regulatory', title: 'HIPAA Compliance for AI Systems',
    summary: 'AI systems processing Protected Health Information (PHI) must comply with HIPAA Privacy, Security, and Breach Notification Rules.',
    content: 'When AI systems access or process PHI, HIPAA requirements apply:\n\n**Privacy Rule** - Establishes minimum necessary standards for PHI use. AI training data must be de-identified per Safe Harbor or Expert Determination methods.\n**Security Rule** - Requires administrative, physical, and technical safeguards for ePHI. AI systems must implement access controls, audit logging, encryption, and transmission security.\n**Breach Notification** - AI-related data breaches affecting PHI must be reported within 60 days.\n**Business Associate Agreements** - Required with AI vendors that process PHI on behalf of covered entities.\n\nForgeAI Govern tracks PHI access per AI system and maps relevant HIPAA controls.',
    frameworks: ['HIPAA', '45 CFR Parts 160, 164'], relevance: 'core',
  },
  {
    id: 'kb-onc-hti1', category: 'regulatory', title: 'ONC HTI-1 Final Rule - Decision Support Interventions',
    summary: 'The ONC HTI-1 rule establishes transparency and risk management requirements for AI-enabled clinical decision support within certified health IT.',
    content: "The ONC Health Data, Technology, and Interoperability (HTI-1) Final Rule introduces requirements for Predictive Decision Support Interventions (DSIs) in certified health IT:\n\n**Source Attribute Transparency** - DSIs must disclose the intervention developer, funding source, and whether the output is based on a predictive model.\n**Risk Management Practices** - Developers must employ practices including bias analysis, validation studies, and ongoing performance monitoring.\n**Intervention Details** - Must be made available including intended use, training data characteristics, and known limitations.\n\nThese requirements align with ForgeAI Govern's AI asset metadata, bias testing, and transparency controls.",
    frameworks: ['ONC HTI-1', '45 CFR Part 170'], relevance: 'core',
  },
  {
    id: 'kb-risk-assessment', category: 'guide', title: 'How to Conduct an AI Risk Assessment',
    summary: 'Step-by-step guide to evaluating AI system risk across 6 dimensions using the ForgeAI weighted scoring model.',
    content: "ForgeAI Govern uses a 6-dimension weighted risk model:\n\n1. **Patient Safety (25%)** - Potential for direct patient harm from incorrect outputs. Score 5 if errors could cause mortality.\n2. **Bias & Fairness (20%)** - Risk of disparate impact across demographic groups. Test with representative populations.\n3. **Data Privacy (15%)** - PHI exposure risk, data minimization compliance, de-identification effectiveness.\n4. **Clinical Validity (15%)** - Scientific evidence supporting the AI's clinical claims. Peer-reviewed validation studies.\n5. **Cybersecurity (15%)** - Attack surface, model poisoning risk, adversarial robustness, API security.\n6. **Regulatory (10%)** - Compliance gaps with FDA, HIPAA, state laws, and organizational policies.\n\n**Overall Risk Calculation:**\n- Critical: weighted score >= 4.0 OR patient safety = 5\n- High: weighted score >= 3.0\n- Moderate: weighted score >= 2.0\n- Low: weighted score < 2.0",
    frameworks: ['NIST AI RMF', 'FDA SaMD'], relevance: 'guide',
  },
  {
    id: 'kb-vendor-due-diligence', category: 'guide', title: 'AI Vendor Due Diligence Best Practices',
    summary: 'Framework for evaluating third-party AI vendors on transparency, bias testing, security, data practices, and contractual provisions.',
    content: "When evaluating AI vendors, assess these 5 dimensions:\n\n1. **Transparency (15%)** - Model architecture disclosure, training data documentation, algorithm explainability.\n2. **Bias Testing (25%)** - Demographic testing methodology, results disaggregation, disparate impact analysis.\n3. **Security (25%)** - SOC 2 compliance, encryption standards, penetration testing, vulnerability management.\n4. **Data Practices (20%)** - Data handling policies, PHI protections, data retention/deletion, sub-processor agreements.\n5. **Contractual (15%)** - Audit rights, SLAs, performance guarantees, liability provisions, exit clauses.\n\n**Scoring:** Each dimension rated 1-5, weighted to produce a 0-100 overall score. Scores below 40 are rejected, 40-60 conditional, above 60 approved.",
    frameworks: ['NIST AI RMF', 'HIPAA BAA'], relevance: 'guide',
  },
  {
    id: 'kb-incident-response', category: 'guide', title: 'AI Incident Response Playbook',
    summary: 'Procedures for responding to AI-related incidents including patient safety events, bias detection, and model failures.',
    content: "ForgeAI Govern supports structured incident response:\n\n**Severity Levels:**\n- **Critical** - Patient safety impact or data breach. Triggers automatic system suspension.\n- **High** - Significant performance degradation or bias detected. Requires 24-hour response.\n- **Moderate** - Notable drift or minor compliance gaps. Requires 72-hour review.\n- **Low** - Informational findings or minor anomalies. Tracked for pattern analysis.\n\n**Response Steps:**\n1. Report incident with severity classification\n2. For critical/patient safety: system auto-suspended pending investigation\n3. Assign investigation team and document root cause\n4. Implement corrective actions with evidence\n5. Review and close with audit trail\n6. Update risk assessment based on findings",
    frameworks: ['NIST AI RMF Manage', 'HIPAA Breach Notification'], relevance: 'guide',
  },
];

export class KnowledgeBaseHandlers {
  async list(ctx) {
    const category = ctx.url.searchParams.get('category');
    const search = ctx.url.searchParams.get('search');

    let filtered = ARTICLES;
    if (category) filtered = filtered.filter(a => a.category === category);
    if (search) {
      const term = search.toLowerCase();
      filtered = filtered.filter(a =>
        a.title.toLowerCase().includes(term) || a.summary.toLowerCase().includes(term) || a.content.toLowerCase().includes(term)
      );
    }
    return jsonResponse({ data: filtered });
  }
}
