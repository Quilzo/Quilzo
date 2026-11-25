// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

// ISO/IEC 42001:2023 Annex A: the controls of an AI management system, each
// by its identifier with a line in Quilzo's own words. The standard's own
// titles and text are ISO's.
var _ = starter(Starter{
	Framework: "iso-42001", Name: "ISO/IEC 42001", Version: "2023, Annex A",
	About: "The international standard for an AI management system, certifiable as ISO/IEC 27001 is.",
	Level: "controls of Annex A",
	Clauses: []Clause{
		{"A.2.2", "A policy for developing and using AI is written"},
		{"A.2.3", "The AI policy fits the organisation's other policies"},
		{"A.2.4", "The AI policy is reviewed at set intervals"},
		{"A.3.2", "Roles for AI are defined and given out"},
		{"A.3.3", "People can raise concerns about AI systems"},
		{"A.4.2", "The resources each AI system needs are recorded"},
		{"A.4.3", "The data an AI system uses is recorded"},
		{"A.4.4", "The tools used for AI systems are recorded"},
		{"A.4.5", "The computing an AI system uses is recorded"},
		{"A.4.6", "The people and skills an AI system needs are recorded"},
		{"A.5.2", "There is a process to assess what an AI system could do to people and society"},
		{"A.5.3", "Impact assessments are recorded and kept"},
		{"A.5.4", "Effects on individuals and groups of people are assessed"},
		{"A.5.5", "Effects on society are assessed"},
		{"A.6.1.2", "Objectives for developing AI responsibly are set"},
		{"A.6.1.3", "Design and development of AI follow a responsible process"},
		{"A.6.2.2", "Requirements for each new AI system are written"},
		{"A.6.2.3", "How an AI system was designed and built is recorded"},
		{"A.6.2.4", "AI systems are verified and validated against their requirements"},
		{"A.6.2.5", "Deployment of an AI system is planned and its conditions met"},
		{"A.6.2.6", "AI systems are operated and monitored"},
		{"A.6.2.7", "Technical documentation is kept for those who need it"},
		{"A.6.2.8", "AI systems keep logs of their events"},
		{"A.7.2", "Data used to develop and improve AI systems is managed"},
		{"A.7.3", "How data is acquired and chosen is recorded"},
		{"A.7.4", "What good data is, is defined, and the data meets it"},
		{"A.7.5", "Where data came from is recorded"},
		{"A.7.6", "How data is prepared is defined and recorded"},
		{"A.8.2", "Users get the information they need about an AI system"},
		{"A.8.3", "Others can report adverse effects of an AI system"},
		{"A.8.4", "Incidents are communicated to those affected"},
		{"A.8.5", "What is owed to interested parties about AI is recorded and given"},
		{"A.9.2", "There is a process for using AI systems responsibly"},
		{"A.9.3", "Objectives for using AI responsibly are set"},
		{"A.9.4", "AI systems are used as intended and as documented"},
		{"A.10.2", "Responsibilities in the AI life cycle are shared out with others who take part"},
		{"A.10.3", "Suppliers of AI services and data meet the organisation's approach"},
		{"A.10.4", "Customers' needs and expectations of AI are considered"},
	},
})
