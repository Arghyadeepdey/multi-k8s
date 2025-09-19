import os
import re
import sys


def parse_anchore_console(file_path: str):
    """
    Parse anchore scan console log to extract packages with Critical severity
    and available FIX version.
    """
    packages = {}

    pattern = re.compile(
        r"│\s*(?:CVE-\d+-\d+|GHSA-[\w-]+)\s*│\s*(Critical|High)\s*│\s*([\w\.\-/]+)\s*│\s*([\w\.\-]+)\s*│\s*([\w\.\-,]+)\s*│\s*false\s*│\s*go\s*│",
        re.IGNORECASE,
    )

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                severity, pkg, version, fix = match.groups()
                # ✅ only keep golang.org/x/* packages
                if pkg.startswith("golang.org/x/") and fix and fix.lower() != "none":
                    chosen_fix = fix.split(",")[0].strip()
                    if not chosen_fix.startswith("v"):
                        chosen_fix = "v" + chosen_fix
                    # keep the lowest fix version if multiple rows
                    if pkg not in packages or packages[pkg] > chosen_fix:
                        packages[pkg] = chosen_fix
    return packages


def generate_go_mod(packages, folder_name: str):
    """
    Write go.mod file with required format.
    """
    os.makedirs(folder_name, exist_ok=True)
    output_path = os.path.join(folder_name, "go.mod")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("module k8s.io/autoscaler/vertical-pod-autoscaler\n")
        f.write("go 1.24\n\n")
        f.write("replace (\n")
        for pkg, fix in sorted(packages.items()):
            f.write(f"{pkg} => {pkg} {fix}\n")
        f.write(")\n")


def extract_image_names(console_file: str) -> list:
    """
    Extract all image names that have golang.org/x/net vulnerabilities.
    """
    # More comprehensive image pattern that captures AWS ECR and other registry formats
    image_pattern = re.compile(r"(?:image:\s*|Scanning image:\s*)([\w\.\-/:@]+)", re.IGNORECASE)
    vulnerability_pattern = re.compile(
        r"│.*golang\.org/x/net.*│",
        re.IGNORECASE,
    )

    image_names = []
    current_image = None

    with open(console_file, "r", encoding="utf-8") as f:
        for line in f:
            # Check if this line contains an image reference
            image_match = image_pattern.search(line)
            if image_match:
                current_image = image_match.group(1)

            # Check if this line contains golang.org/x/net vulnerability
            vuln_match = vulnerability_pattern.search(line)
            if vuln_match and current_image:
                # Extract image name from full path
                # Example: 527856644868.dkr.ecr.us-east-2.amazonaws.com/thirdparty/kube-controller-manager:v1.32.6
                # Extract: kube-controller-manager
                image_name = current_image.split("/")[-1]  # kube-controller-manager:v1.32.6
                image_name = image_name.split(":")[0]  # kube-controller-manager

                # Add to list if not already present
                if image_name not in image_names:
                    image_names.append(image_name)

    return image_names if image_names else ["unknown-image"]

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python findpackages.py <console.txt> <go.mod>")
        sys.exit(1)
    #console_file = "/Users/arghdey/Documents/revisedconsole.txt"
    #go_mod_file ="go.mod"
    console_file = sys.argv[1]
    go_mod_file = sys.argv[2]

    pkgs = parse_anchore_console(console_file)
    image_names = extract_image_names(console_file)

    print(f"Image names with golang.org/x/net vulnerabilities: {image_names}")

    # Generate go.mod files for each image
    for image_name in image_names:
        generate_go_mod(pkgs, image_name)
        print(f"go.mod generated for {image_name}")

    print(f"Processing completed for {len(image_names)} images")

    print(f"go.mod generated at {go_mod_file}")
