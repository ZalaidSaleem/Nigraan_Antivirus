function get_scan_results(results) {
     $.ajax(
        {
            type: 'POST',
            cache: false,
            data : {
                request : 'scan'
            },
            url: '/scan/results',
            dataType : "json",
            success : function (data) {
                // Create tooltips for the circle charts
                var tooltips = {
                    'circles-1': 'Initial Prediction: This score shows the malware probability based on raw feature analysis. Higher values indicate a higher likelihood of malicious content.',
                    'circles-2': 'Rectification Value: This represents the adjustment made after deeper analysis to reduce false positives. Positive values increase malware probability, negative values decrease it.',
                    'circles-3': 'Final Verdict: The final malware probability score after all analysis and rectification. Values over 50% classify the file as likely malicious.'
                };
                
                // First circle - initial prediction
                Circles.create({
                    id:'circles-1',
                    radius:45,
                    value:Math.round(data.pre_prediction*100)/100 *100,
                    maxValue:100,
                    width:7,
                    text: Math.round(data.pre_prediction*100)/100 *100 + '%',
                    colors: get_color(parseFloat(data.pre_prediction)),
                    duration:500,
                    wrpClass:'circles-wrp',
                    textClass:'circles-text',
                    styleWrapper:true,
                    styleText:true
                });
                
                // Add tooltip to the first circle
                $('#circles-1').parent().attr('title', tooltips['circles-1']);
                $('#circles-1').parent().attr('data-toggle', 'tooltip');
                $('#circles-1').parent().tooltip();
                
                // Second circle - rectification
                Circles.create({
                    id:'circles-2',
                    radius:45,
                    value:Math.round(data.rectification*100)/100 *100,
                    maxValue:100,
                    width:7,
                    text: Math.round(data.rectification*100)/100 *100+ '%',
                    colors:['#f1f1f1', '#2c91b9'],
                    duration:500,
                    wrpClass:'circles-wrp',
                    textClass:'circles-text',
                    styleWrapper:true,
                    styleText:true
                });
                
                // Add tooltip to the second circle
                $('#circles-2').parent().attr('title', tooltips['circles-2']);
                $('#circles-2').parent().attr('data-toggle', 'tooltip');
                $('#circles-2').parent().tooltip();
                
                // Third circle - final verdict
                Circles.create({
                    id:'circles-3',
                    radius:45,
                    value:Math.round(data.rectified*100)/100 *100,
                    maxValue:100,
                    width:7,
                    text: Math.round(data.rectified*100)/100 *100+'%',
                    colors: get_color(parseFloat(data.rectified)),
                    duration:500,
                    wrpClass:'circles-wrp',
                    textClass:'circles-text',
                    styleWrapper:true,
                    styleText:true
                });
                
                // Add tooltip to the third circle
                $('#circles-3').parent().attr('title', tooltips['circles-3']);
                $('#circles-3').parent().attr('data-toggle', 'tooltip');
                $('#circles-3').parent().tooltip();
                
                let score = parseFloat(data.rectified);
                if (score < 0.5){
                    $("#infection").html("Clear");
                }else{
                    $("#infection").html("Infected");
                }

                $("#sha256").html("<h6 class=\"fw-bold text-uppercase text-default op-8\" >"+data.hash+"</h6>");
                $("#time").text(data.time + 's');
                $("#file_size").text(data.file_size + 'KB');

                for(let i = 0; i<data.grams.length;i++){
                    results[i] = data.grams[i];
                }
                var str_replaced = data.imports.replace(/'/g, '"');
                var obj = JSON.parse(str_replaced);
                var str = JSON.stringify(obj, undefined, 4);
                output(syntaxHighlight(str));

                // Update grams chart with actual data from scan
                if (window.statisticsChart && data.grams && data.grams.length > 0) {
                    // Take first 12 elements or pad with zeros if less than 12
                    let gramData = data.grams.slice(0, 12);
                    while (gramData.length < 12) {
                        gramData.push(0);
                    }
                    
                    // Update the third dataset (current file analysis)
                    window.statisticsChart.data.datasets[2].data = gramData.map(val => val * 1000); // Scale for better visualization
                    window.statisticsChart.update();
                    
                    // Add explanation text
                    $('#grams-explanation').html(
                        '<div class="alert alert-info">' +
                        '<strong>Byte 4-Grams Analysis</strong><br>' +
                        'This chart shows the distribution of byte patterns (4-grams) in the file. ' +
                        'The orange line represents typical patterns in malware, red line shows typical ' +
                        'benign file patterns, and blue shows the current file. ' +
                        'Similar patterns to malware may indicate malicious behavior.' +
                        '</div>'
                    );
                }
            },
            error : function (jqXHR) {
                alert("error: " + jqXHR.status);
                $("#scp").append("<script>" +
                    "                var x = [];\n" +
                    "                for (var i = 0; i < 500; i ++) {\n" +
                    "                    x[i] = Math.random();\n" +
                    "                }\n" +
                    "\n" +
                    "                var trace = {\n" +
                    "                    x: x,\n" +
                    "                    type: 'histogram',\n" +
                    "                  };\n" +
                    "                var datax = [trace];\n" +
                    "                Plotly.newPlot('MyDiv', datax);" +
                    "</script>");
            }
        }
    );
}


function get_color(score) {
    if(score>0.5){
        return ['#f1f1f1', '#F25961'];
    }else if(score<0.5){
        return ['#f1f1f1', '#2BB930'];
    }
}

function output(inp) {
    $("#dlls_div").append($("<pre></pre>").html(inp))
}


function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/<//g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        var cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}


function show_feature(e) {
    e.preventDefault();
    let id = $(`#${e.target.id}`).html();
    
    // Add explanations for each feature view
    const explanations = {
        '4-grams': 'The 4-grams analysis examines patterns of 4 consecutive bytes in the file. ' +
                   'Certain byte patterns are more common in malicious files than in legitimate software. ' +
                   'The chart shows how the current file\'s patterns compare to known benign and malicious files.',
        
        'dlls': 'This section shows the DLL libraries and API functions imported by the executable. ' +
               'Malware often uses specific combinations of system functions to perform malicious activities. ' +
               'Pay attention to suspicious combinations like memory manipulation with file/registry access.',
        
        'images': 'The binary visualization represents the file as an image where each pixel corresponds to a byte value. ' +
                  'Different types of files and malware families often have distinctive visual patterns.',
        
        'sequence': 'This analysis examines the sequence of assembly instructions in the executable. ' +
                    'Malicious code often exhibits unusual instruction patterns like excessive obfuscation or evasion techniques.'
    };
    
    if(id == '4-grams'){
        $('#grams_f').attr('style', 'display: inline');
        $('#dlls_div').attr('style', 'display: none');
        $('#feature-explanation').html('<div class="alert alert-info">' + explanations['4-grams'] + '</div>');
    } else if(id == 'dlls') {
        $('#grams_f').attr('style', 'display: none');
        $('#dlls_div').attr('style', 'display: block');
        $('#feature-explanation').html('<div class="alert alert-info">' + explanations['dlls'] + '</div>');
    } else if(id == 'images') {
        $('#grams_f').attr('style', 'display: none');
        $('#dlls_div').attr('style', 'display: none');
        $('#feature-explanation').html('<div class="alert alert-info">' + explanations['images'] + '</div>');
    } else if(id == 'sequence') {
        $('#grams_f').attr('style', 'display: none');
        $('#dlls_div').attr('style', 'display: none');
        $('#feature-explanation').html('<div class="alert alert-info">' + explanations['sequence'] + '</div>');
    }
}

/**
 * Updates the color of visualization elements based on the score
 * @param {number} score - Malware probability score (0-1)
 * @returns {Array} - Array of colors for visualization
 */
function get_color(score) {
    if(score>0.5){
        return ['#f1f1f1', '#F25961'];  // Red for malicious
    }else if(score<0.5){
        return ['#f1f1f1', '#2BB930'];  // Green for benign
    }
}