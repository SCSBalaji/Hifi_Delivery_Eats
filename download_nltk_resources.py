#!/usr/bin/env python3
"""
Download required NLTK resources for the application.
Run this script before starting the application for the first time.
"""
import sys

try:
    import nltk
    
    # Download necessary resources with quiet mode and error handling
    resources = ['punkt', 'stopwords', 'wordnet', 'averaged_perceptron_tagger', 'punkt_tab']
    
    for resource in resources:
        try:
            nltk.download(resource, quiet=True)
            print(f"✓ Downloaded {resource}")
        except Exception as e:
            print(f"⚠ Warning: Could not download {resource}: {e}")
    
    print("\nNLTK resources setup complete!")
    
except ImportError:
    print("NLTK is not installed. Please run: pip install nltk")
    sys.exit(1)
except Exception as e:
    print(f"Error setting up NLTK: {e}")
    sys.exit(1)
