---
title: "Vibe coding a Mach-o parser"
date: "2025-04-13"
url: "/posts/Vibe-coding-a-Macho-Parser/"
tags:
  - "ai"
  - "macos"
  - "security"
---

Way back in 2021 when I was working on my [dissertation](https://github.com/kimobu/lhtml) I used a Python library called [macholibre](https://github.com/aaronst/macholibre) to parse Mach-O files. There are [several other options](https://github.com/search?q=macho%20parser&type=repositories) for parsing these file types. I'm sure they're all great, but it's a lot to go through to find some features I want. Mainly, outputting as JSON to easily load into other applications. This seemed like a good opportunity to try [vibe-coding](https://en.wikipedia.org/wiki/Vibe_coding) a Swift-based Mach-O parser using ChatGPT. After some trial and error, I've made [MachP](https://github.com/kimobu/machp) available. Let's look at how this went.

# Writing Requirements
Since vibe-coding is basically delegating coding tasks like a manager would, I wanted to clearly define requirements for the LLM to use. I had a general idea of what I wanted and enough knowledge of what Mach-O file looks like. To help turn those ideas into specific requirements I turned to OpenAI's Deep Research tool.

> Let’s design a macho file parsing utility. The input will be a file name. The utility should open that file and then parse the macho. Consider that a macho may be a fat binary with multiple architecture machos. We should parse the header, load commands, and all data segments. We should get the size and name of each element. The output should be in json format. One of the use cases for this utility is to parse out features that can be used for machine learning purposes. The utility should be written in swift. For this research, output a set of well defined requirements that will be fed into a reasoning model for implementation

Deep Research asks some follow-ups to help scope its work. After it performed its searches, it returned the following requirements. I'm only including the requirement titles for brevity. For each requirement it provided roughly a paragraph of what should be done.
**Functional Requirements**
- Input Handling
- Mach-O Format Support
- Mach-O Header Parsing
- Load Command Parsing
- Segment and Section Parsing
- Metadata Extraction
- JSON Output
- Graceful Error Handling
- Current macOS Focus
 **Non-Functional Requirements**
- Performance
- Resource Usage
- Reliability and Stability
- Maintainability
- Usability
- Output Clarity
- Platform Compatibility
 **Optional Features**
- Raw Data Extraction Mode
- Recursive Bundle Parsing
- Verbose Logging/Debug Mode
- Extensibility for Other Binary Formats
# Coding
With those requirements made, I continued the chat with:
>Next lets get started with setting up the project. I've created a new project in XCode. What files will we need to create?

ChatGPT listed out - main.swift, MachOParser.swift, HeaderParser.swift, LoadCommandParser.swift, SegmentSectionParser.swift, JSONOutputFormatter.swift, ErrorHandling.swift, Utilities.swift. I ended up cutting out ErrorHandling and Utilities. 

The ChatGPT desktop app can "work with" other apps to gain context (read what's currently open in the app) and to output (write to the app). It supports Xcode, so at this point I opened Xcode, created each file the model suggested, and asked it to implement the functionality that I thought should go in each one.

Once the initial implementation was made, I started to iteratively test and adjust the functionality. I'd build the tool, run it against some test files, then compare to the output to what I expected and against a Yara-X benchmark. I'd then ask the model to tweak some functionality, then repeat the testing.

In a couple of places I hit some sticky problem areas. In those cases, I'd create a new chat so there was fresh context and the model wouldn't be "polluted" with previous messages. This can be especially helpful if chats grow too long. One area in particular was parsing out code signature information. I ended up pasting the contents of cscdefs.h into chat so the model better understood what data structures were there, asked it to iterate on code to parse the structures, and would compare what the program output to a hex editor to make sure the model's code was reading the write offsets and such. This helped to identify that In the initial implementation, the model's code was reading offsets from the start of the file instead of from the starting offset of individual Mach-Os embedded in a universal binary.

There were only a few instances where the model hallucinated information. One example is, when trying to parse the code signature, the model tried using a function `SecRequirementCopyStringRepresentation` which does not exist. Steering it to the actual function `SecRequirementCopyString` worked. The model had the right parameters to the function, just the name was wrong.

Another tip is to sometimes reduce the information that the model has access to. For example, giving context to the ChatGPT app via "work with files" is very useful so the model can better understand what is or should be happening. However, sometimes the tool that writes to the file messes up. If you find that the app starts writing to the wrong file or fails to write, try closing editor tabs so it can focus on a specific file.

## Codex
Codex proved incredibly useful, because instead of needing to be at the computer interacting with ChatGPT, I could define a few feature requests, kick them off as Codex tasks, and then go AFK to do real work, deal with life, etc. Of the eight Codex tasks requested, I merged seven of them. Most of these required no modifications. The only task I needed to edit code for was from a requirement I gave that showed base64 output when I really wanted plaintext, so I needed to remove the call to `base64EncodedString`. 

The Codex PR I did not merge was related to test writing. The model tried to write tests for each module but could not import `CryptoKit`. Since Codex runs in an Ubuntu container, it doesn't have access to Apple's APIs. Not being a big Swift developer, it took a bit of searching to learn that you can install Swift on macOS, Linux, and Windows, but you need to rely on some re-implementations of APIs if you are not on macOS. In the case of CryptoKit you'd use [swift-crypto](https://github.com/apple/swift-crypto). I converted the MachP code to import Crypto instead of CryptoKit and it functionally still worked, so I thought it'd be straightforward to add it to Codex.

OpenAI lets you modify the environment for Codex, so I tried to add Swift to it via the startup scripts:
```bash
curl -O "https://download.swift.org/swiftly/linux/swiftly-$(uname -m).tar.gz" && \
tar zxf "swiftly-$(uname -m).tar.gz" && \
./swiftly init --assume-yes --quiet-shell-followup && \
. ${SWIFTLY_HOME_DIR:-~/.local/share/swiftly}/env.sh && \
hash -r
```

This works, however Codex can't use the Internet once the container has started. Because of this, it can't download dependencies like `swift-log` or `swift-crypto`. I also don't see a way to install Swift packages outside of a manifest to pre-populate the dependencies during the container initialization. It looks like [the people want it](https://forums.swift.org/t/implement-an-install-command-for-the-swift-package-manager/10148/13) but the `install-package` subcommand does not yet exist :(

_2025-06-03 update_: OpenAI announced [networking for Codex](https://platform.openai.com/docs/codex/agent-network). This introduces some security risk, but it's now an option for testing Swift packages.
# Model switching
Throughout the process I switched models depending on the task. It's a meme at this point that OpenAI's naming convention is terribad, so it seems like it might be useful to discuss when and how I used each model.

During the requirements writing phase, I used 4o, since it's a conversational model and we were having a discussion on what the requirements should be. During coding, I mostly used o3-mini and during some troubleshooting I occasionally used o3-mini-high. These reasoning models were better suited for understanding what the requirement meant and turning that into code. Part way through this project, OpenAI released 4.1 as a model to ChatGPT. Previously this model was only available through the API. The 4.1 model is better at coding and is "smarter" than 4o, but it isn't as optimized for chat (which is why it's "hidden" under a dropdown in the model picker). Finally, once Codex was released I used the codex-1 model by proxy.

So to summarize:
- Use 4o when "talking" to a model
- Use 4.1 when troubleshooting or doing light code touchups
- Use o3-* when designing and writing larger code sections
- Use codex-1 when using Codex
