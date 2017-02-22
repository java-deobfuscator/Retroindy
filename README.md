# Retroindy

[![Build Status](https://ci.samczsun.com/job/java-deobfuscator/job/Retroindy/badge/icon)](https://ci.samczsun.com/job/java-deobfuscator/job/Retroindy/)
  

~~Some~~ All decompilers have some trouble with Java 8 features, like `invokedynamic`
and `ldc`-ing `MethodType` and `MethodHandle`. It's makes it a huge pain when trying to decompile something
because you have to go through the disassembly and whatever. Instead, run it through this Retroindy first and see
if the program is actually as hard to read as you thought it was.

Note that the resulting program **is not** semantically equivalent to the original code.
For one, the call stack during bootstrapping will be different. Do not attempt to use the
resulting program in production!

## Download

Builds can be downloaded from [the CI](https://ci.samczsun.com/job/java-deobfuscator/job/Retroindy/)

## Usage

`java -jar retroindy.jar [input.jar]`
  
Saves to `input-retro.jar`

## Example

### Before
```java
    public class Test {
        private static final MethodHandle[] a = new MethodHandle[4];
        
        static {
            a[0] = /* methodhandle */ null;    
            a[1] = /* methodhandle */ null;    
            a[2] = /* methodhandle */ null;    
            a[3] = /* methodhandle */ null;    
        }
        
        public static void main(String[] args) {
            System.out.<invokedynamic>a(1750247380, "Hello world");
        }
    }
```

## After

```java
   public class Test { 
       private static final MethodHandle[] a = new MethodHandle[4];
       private static AtomicReferenceArray CALLSITE_CACHE = new AtomicReferenceArray(new Object[1]);
    
       static {
          a[0] = MethodHandles.lookup().findVirtual(Thread.class, "getStackTrace", asMethodType("()[Ljava/lang/StackTraceElement;"));
          a[1] = MethodHandles.lookup().findVirtual(String.class, "getBytes", asMethodType("()[B"));
          a[2] = MethodHandles.lookup().findStaticGetter(System.class, "out", PrintStream.class);
          a[3] = MethodHandles.lookup().findStaticGetter(System.class, "out", PrintStream.class);
       }
       
       public static void INDY_0(PrintStream stream, String message) {
          if(CALLSITE_CACHE.get(0) == null) {
             CALLSITE_CACHE.compareAndSet(0, (Object)null, bootstrapMethod(MethodHandles.lookup(), "a", asMethodType("(Ljava/lang/String;)V"), 1750247380));
          }
    
          return (PrintStream)((CallSite)CALLSITE_CACHE.get(0)).getTarget().invokeExact(stream, message);
       }
       
       public static void main(String[] args) {
           INDY_0(System.out, "Hello world");
       }
   }
```