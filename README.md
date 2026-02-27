# Empathy Encryption – Hackathon Winning Python Submission 🥇 

This repository contains my original Python submission for  
**The Empathy Encryption Hackathon**, where I secured 🥇 1st Rank.

---

## Project Philosophy

This is not a traditional rule-based password validator.

Instead of rigid enforcement, the system evaluates passwords using
**human-centered heuristics**, inspired by product thinking:

- Reasonable Security
- Intentionality
- Visual Clarity
- Balance
- Human Structure

The validator uses weighted scoring rather than binary checks,
mimicking how a thoughtful product team would evaluate real-world inputs.

---

## Core Techniques Used

- Shannon Entropy Analysis
- Unique Character Ratio Detection
- Keyboard Walk Detection
- Repetition Scoring
- Regex-Based Human Structure Detection
- Weighted Acceptance Threshold System

Time Complexity: O(n)  
Space Complexity: O(n)

---

## Run Locally

```bash
python empathy_password_validator.py
```
---

## Includes:

- 10 accepted password test cases
- 10 rejected password test cases
- Clear reasoning comments inline

---

## Related Work

After the hackathon, I independently rebuilt and deployed
the same concept using Node.js:

👉 https://github.com/Shreeja-88/empathy-encryption-engine

This allowed me to explore scalability and real-world implementation.
Built with a product-first mindset under competitive constraints.
