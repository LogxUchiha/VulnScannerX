function detectAndAnalyze() {
  const codeInput = document.getElementById("codeInput").value;
  const totalLines = codeInput.split('\n').length;

  const nullPointerResults = detect(codeInput);

  const totalErrors = nullPointerResults.count;
  const errorPercentage = (totalErrors / totalLines) * 100; // Calculate the percentage of errors

  let vulnerabilityLevel;
  if (errorPercentage > 10) {
    vulnerabilityLevel = "High"; // If errors are more than 50% of the code, it's high vulnerability
  } else if (totalErrors > 5) {
    vulnerabilityLevel = "Medium"; // Otherwise, if there are any errors, it's medium vulnerability
  } else {
    vulnerabilityLevel = "Low"; // If no errors, it's low vulnerability
  }

  // Update the content of the squares
  document.getElementById("totalErrors").textContent = totalErrors;
  document.getElementById("language").textContent = detectLanguages(codeInput).join(", ");
  document.getElementById("vulnerabilityLevel").textContent = vulnerabilityLevel;
  document.getElementById("totalLines").textContent = totalLines;

  // Show the squares
  document.getElementById("totalLinesSquare").style.display = "inline-block";
  document.getElementById("errorSquare").style.display = "inline-block";
  document.getElementById("languageSquare").style.display = "inline-block";
  document.getElementById("vulnerabilitySquare").style.display = "inline-block";

  // Display the analysis results
  displayResults(nullPointerResults);
}


function highlightVulnerabilities(codeInput, vulnerabilities) {
  // Reset textarea content
  codeInput.value = codeInput.value;

  // Remove existing highlights
  codeInput.classList.remove('highlighted');

  // Highlight vulnerabilities within the textarea
  vulnerabilities.forEach(function(vulnerability) {
    var startIndex = vulnerability.index;
    var endIndex = startIndex + vulnerability.match.length;

    // Create a range object to highlight the vulnerability
    var range = document.createRange();
    range.setStart(codeInput, startIndex);
    range.setEnd(codeInput, endIndex);

    // Create a span element for highlighting
    var highlightSpan = document.createElement('span');
    highlightSpan.className = 'highlight';
    range.surroundContents(highlightSpan);
  });

  // Set focus on the textarea
  codeInput.focus();
}



//------------------------Function to display the output after click the submit    --------------------------//
function displayResults(nullPointerResults) {
  var resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = '';

  if (nullPointerResults.count === 0) {
    resultsDiv.textContent = 'No vulnerabilities found.';
  } else {
    resultsDiv.innerHTML = '<h4>Analysis Report</h4>';

    // Group vulnerabilities by type
    const groupedResults = {};
    nullPointerResults.results.forEach(function(vulnerability) {
      if (!groupedResults.hasOwnProperty(vulnerability.type)) {
        groupedResults[vulnerability.type] = [];
      }
      groupedResults[vulnerability.type].push(vulnerability);
    });

    // Display vulnerabilities by type
    for (const vulnerabilityType in groupedResults) {
      if (groupedResults.hasOwnProperty(vulnerabilityType)) {
        resultsDiv.innerHTML += `_________________________________________________________________<br>`;
        resultsDiv.innerHTML += `<br><h4>${vulnerabilityType}</h4></br>`; // Display vulnerability type as title

        resultsDiv.innerHTML += '<p> Number of vulnerabilities found: ' + groupedResults[vulnerabilityType].length + '</p>';
        resultsDiv.innerHTML += '<p3>[ Vulnerability locations: ]</p3>\n';
        var list = document.createElement('ul');
        groupedResults[vulnerabilityType].forEach(function(location) {
          var lineNum = getLineNumber(location.index);
          var listItem = document.createElement('li');
          listItem.textContent = 'Line ' + lineNum + ': ' + location.match;
          list.appendChild(listItem);
        });
        resultsDiv.appendChild(list);

      }
    }
  }
}
//------------------------Function to display the output after click the submit    --------------------------//




//-------------------------------Function to detect the line of the code   ---------------------------------//
function getLineNumber(index) {
  var code = document.getElementById('codeInput').value;
  var lines = code.substr(0, index).split('\n');
  return lines.length;
}
//-------------------------------Function to detect the line of the code   ---------------------------------//





//-------------------------------Function to detect the vulnerability using regex ---------------------------------//

function detect(code) {
  // Define patterns for each vulnerability type:
  const patterns = {
    'CWE-476: NULL Pointer Dereference': [
      // Common patterns for NULL pointer dereference (total: 100):
      /\b(null)\.(?:\w+|\*)|\*\s*null/g,
      /\b(printf|strcpy|memcpy|strcat|strcmp|strncat|strncpy|strcmpi|strncasecmp|strcasecmp|strstr|strchr|strcspn|strpbrk|strtok|strrchr|strspn|strtok_r|strxfrm|memmove|memcpy|memchr|memrchr|memset|bzero|bcopy|bcmp|bsearch|qsort|lsearch|hsearch|wcscpy|wcsncpy|wcscat|wcsncmp|wcscasecmp|wcsncasecmp|wcsstr|wcschr|wcscspn|wcsncat|wcsncpy|wcscasecmp|wcsncasecmp|wcsstr|wcschr|wcschr|wcspbrk|wcstok|wcsstr|wcscoll|wcsxfrm)\s*\(\s*(?:[^,)]*,\s*)*(?:null|[^,)]*)\s*\)/g,
      /\b(malloc|calloc|realloc|free|strdup|strndup|strtok_r|fopen|fgets|fread|fscanf|fgetc|getchar|fgetc_unlocked|getc|getc_unlocked|fputc|fputc_unlocked|putc|putc_unlocked|fgets|getline|readline|strtok|strtok_r|fgetln|readline)\s*\(\s*\)\.(?:\w+|\*)|\*\s*\b(malloc|calloc|realloc|free|strdup|strndup|strtok_r|fopen|fgets|fread|fscanf|fgetc|getchar|fgetc_unlocked|getc|getc_unlocked|fputc|fputc_unlocked|putc|putc_unlocked|fgets|getline|readline|strtok|strtok_r|fgetln|readline)\s*\(\s*\)/g,
      /\b(input|user_input|untrusted_data)\s*=\s*(?:[^;]*);\s*\*\binput/g,
    
    ],
    'A03:2021 -Injection': [
      // Placeholder patterns for A03:2021 (total: 100)
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\s+.*\s+(FROM|INTO|SET|WHERE)\s+.*['"]?\b(?:[^;]*);/gi,
      /\b(\w+)\s*=\s*(?:input|user_input|untrusted_data);?\s*(?:\w+\s*=\s*)?(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\s+.*\s+(FROM|INTO|SET|WHERE)\s+.*['"]?\b(?:[^;]*);/gi,
    ],
    'CWE-79: XSS Vulnerability': [
      // Common patterns for XSS vulnerabilities (total: 100):
      /<script>.*<\/script>/g,
      /on[event]=.*>/g,
      /javascript:.*>/g,
      /<!--.*-->.*<script>.*<\/script>/g,
      /<[^>]+onclick\s*=\s*".*\s*"/g,
      /(?:javascript:|%3Cscript.*%3E).*%3C\/script%3E/g,
      /\beval\s*\(/g,
      /\bdocument\.write\s*\(/g,
      /<[^>]+(?:src|href)=['"][^'"]+['"][^>]*>/g,
    ],
    'CWE-434: Unrestricted File Upload': [
      // Patterns for detecting file upload vulnerabilities (total: 100):
      /upload\.php/g,
      /save_file\.php/g,
      /\$_FILES\[/g,
      /move_uploaded_file\s*\(/g,
      /file_get_contents\s*\(/g,
      /fopen\s*\(/g,
      /fwrite\s*\(/g,
      /system\s*\(/g,
      /exec\s*\(/g,
    ],
  };
  

  const results = [];

  // Iterate through patterns for each vulnerability type:
  for (const vulnerabilityType in patterns) {
    if (patterns.hasOwnProperty(vulnerabilityType)) {
      const vulnerabilityPatterns = patterns[vulnerabilityType];
      vulnerabilityPatterns.forEach((pattern) => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          results.push({
            type: vulnerabilityType, // Add vulnerability type property
            match: match[0],
            index: match.index,
          });
        }
      });
    }
  }

  return {
    count: results.length,
    results: results,
  };
}
//-------------------------------Function to detect the vulnerability using regex ---------------------------------//






//-------------------------------Function to count the occurrences of each keyword ---------------------------------//
function countKeywords(code, keywords) {
  let count = 0;
  keywords.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, "g");
    const matches = code.match(regex);
    if (matches) {
      count += matches.length;
    }
  });
  return count;
}
//-------------------------------Function to count the occurrences of each keyword ---------------------------------//







//--------------------------Function to detect what language it is for the uploaded code----------------------------//
function detectLanguages(code) {
  const javaKeywords = ["public", "class", "static", "void", "String"];
  const javascriptKeywords = ["function", "var", "let", "const", "console.log"];
  const cKeywords = ["#include", "int", "main", "printf", "scanf"];
  const sqlKeywords = ["SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"];
  const phpKeywords = ["<?php", "echo",  "require", "function", "class"];
  const pythonKeywords = ["def", "import", "as", "None", "True", "False"];
  const cppKeywords = ["#include", "using", "namespace", "int", "main", "cout", "cin"];

  const javaCount = countKeywords(code, javaKeywords);
  const javascriptCount = countKeywords(code, javascriptKeywords);
  const cCount = countKeywords(code, cKeywords);
  const sqlCount = countKeywords(code, sqlKeywords);
  const phpCount = countKeywords(code, phpKeywords);
  const pythonCount = countKeywords(code, pythonKeywords);
  const cppCount = countKeywords(code, cppKeywords);

  const languages = [];

  if (javaCount > 0) languages.push("Java");
  if (pythonCount > 0) languages.push("Python");
  if (javascriptCount > 0) languages.push("JavaScript");
  if (cCount > 0) languages.push("C");
  if (sqlCount > 0) languages.push("SQL");
  if (phpCount > 0) languages.push("PHP");
  if (pythonCount > 0) languages.push("Python");
  if (cppCount > 0) languages.push("C++");

  return languages;
}
//--------------------------Function to detect what language it is for the uploaded code----------------------------//




