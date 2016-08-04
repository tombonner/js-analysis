/*

	File:		redefine.js

	Author:		Tom Bonner (tom.bonner@gmail.com)

	Date:		10-June-2016

	Version:	0.2

	Purpose:	Use with SpiderMonkey for analysing JS malware.

	Copyright (C) 2016, Tom Bonner.

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


*/

//
// Main logging funtion
//

log = function(id, message) {
    print(id + " - " + message);
};

//
// Redefine DOM for browser based malware
//

document = {
    elements: {},
    referrer: "http://localhost/",
    lastModified: new Date().toLocaleString(),
    write: function(markup) {
        log("document.write", markup);
    },
    writeln: function(markup) {
        log("document.writeln", markup);
    },
    location: function(url) {
        log("document.location", url);
    },
    getElementById: function(id) {
        log("document.getElementById", id);
        return this.elements[id];
    },
    appendChild: function(child) {
        log("document.appendChild", JSON.stringify(child, null, 4));
    },
    createElement: function(name) {
        log("document.createElement", name);
        var element = {
            name: name,
            elements: [],
            setAttribute: function(name, attribute) {
                this[name] = attribute;
                log(this.name + ".setAttribute", attribute)
            },
            appendChild: function(child) {
                this.elements.push(child);
                log(this.name + ".appendChild", JSON.stringify(child, null, 4))
            },
            set url(url) {
                this["_url"] = url;
                log(this.name + ".url", url);
            },
            style: {},
            name: name,
            rawParse: function(str) {
                log(this.name + ".rawParse", str);
            }
        };
        this.elements[name] = element;
        return element;
    },
    body: {
        elements: [],
        appendChild: function(child) {
            this.elements.push(child);
            log("document.body.appendChild", JSON.stringify(child, null, 4));
        }
    }
};

window = {
    eval: print,
    top: 0,
    bottom: 0,
    left: 0,
    right: 0,
    location: {
        href: "http://localhost/"
    },
    navigate: function(url) {
        log("window.navigate", url);
    },
};

location = {
    href: "http://localhost/"
}

eval = function(code) {
    print(code);
}

console = {
    log: print
};

//
// Redefine objects for PDF based malware
//

app = {
    setTimeOut: function(code, timeout) {
        log("app.setTimeout", timeout);
        eval(code);
        return {}
    },
    clearTimeOut: function(id) {
        log("app.clearTimeOut", id);
        return {}
    },
    viewerVersion: "8.1"
};

Collab = {
    collectEmailInfo: function(info) {
        log("Collab.collectEmailInfo", "Subject: " + info.subj + ", Message:" + info.msg);
        return {}
    }
}

//
// Ensure malware cannot use the system command!
//

system = print;

//
// Dump global variables
//

var baseGlobalKeys = Object.keys(this);

function dump() {
    // Dump any changes to window/document
    print("window:" + JSON.stringify(window, null, 4));
    print("document:" + JSON.stringify(document, null, 4));

    // Dump any new global variables
    var globalKeys = Object.keys(this);

    for (var i = 0; i < globalKeys.length; i++) {
        var key = globalKeys[i];
        var found = false;

        for (var j = 0; j < baseGlobalKeys.length; j++) {
            if (key == baseGlobalKeys[j]) {
                found = true;

                break;
            }
        }

        if (found == false) {
            print(key + ":" + JSON.stringify(this[key], null, 4));
        }
    }
}

//
// ToDo: XOR shellcode scanning
//

function shellcode() {

}