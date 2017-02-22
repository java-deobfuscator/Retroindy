/*
 * Copyright 2017 Sam Sun <github-contact@samczsun.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.javadeobfuscator.retroindy;

import org.apache.commons.io.IOUtils;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.objectweb.asm.Opcodes.*;

public class Retroindy {
    public static void main(String[] args) throws Throwable {
        if (args.length == 0) {
            System.out.println("An input JAR must be specified");
            return;
        }

        File in = new File(args[0]);

        if (!in.exists()) {
            System.out.println("Input not found");
            return;
        }

        String outName = args[0];
        outName = outName.substring(0, outName.length() - ".jar".length()) + "-retro.jar";

        File out = new File(outName);

        if (out.exists()) {
            if (!out.delete()) {
                System.out.println("Could not delete out file");
                return;
            }
        }

        try (ZipOutputStream outstream = new ZipOutputStream(new FileOutputStream(out));
             ZipFile zipFile = new ZipFile(in)) {

            Enumeration<? extends ZipEntry> enumeration = zipFile.entries();

            while (enumeration.hasMoreElements()) {
                ZipEntry next = enumeration.nextElement();

                if (!next.isDirectory()) {
                    ZipEntry result = new ZipEntry(next.getName());
                    outstream.putNextEntry(result);
                    if (next.getName().endsWith(".class")) {
                        byte[] classBytes = IOUtils.toByteArray(zipFile.getInputStream(next));
                        outstream.write(transform(classBytes));
                    } else {
                        IOUtils.copy(zipFile.getInputStream(next), outstream);
                    }
                    outstream.closeEntry();
                }
            }
        }
    }

    private static byte[] transform(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);

        ClassNode classNode = new ClassNode();
        reader.accept(classNode, 0);

        handleIndy(classNode);
        handleLdcMethodHandle(classNode);
        handleLdcMethodType(classNode);

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        classNode.accept(writer);
        return writer.toByteArray();
    }

    /**
     * This one takes any instruction in the form of
     * <p><blockquote><pre>
     *     MethodType x = ldc MethodType("()V"); // cannot be expressed in source code
     * </pre></blockquote></p>
     * and transforms it to
     * <p><blockquote><pre>
     *     MethodType x = asMethodType("()V");
     * </pre></blockquote></p>
     * It also creates a helper function {@code asMethodType} with the following content
     * <p><blockquote><pre>
     *     private static MethodType asMethodType(String arg0) {
     *         return MethodType.fromMethodDescriptorString(arg0, CurrentClass.class.getClassLoader());
     *     }
     * </pre></blockquote></p>
     */
    private static void handleLdcMethodType(ClassNode classNode) {
        String asMethodTypeName = "asMethodType";
        String asMethodTypeDesc = "(Ljava/lang/String;)Ljava/lang/invoke/MethodType;";
        {
            Set<String> blacklisted = new HashSet<>();
            for (MethodNode methodNode : classNode.methods) {
                if (methodNode.desc.equals(asMethodTypeDesc) && methodNode.name.startsWith(asMethodTypeName)) {
                    blacklisted.add(methodNode.name);
                }
            }
            if (!blacklisted.add(asMethodTypeName)) {
                for (int i = 0; i < Integer.MAX_VALUE; i++) {
                    if (blacklisted.add(asMethodTypeName + i)) {
                        asMethodTypeName += i;
                        break;
                    }
                }
            }
        }

        MethodNode asMethodType = new MethodNode(Opcodes.ASM5, Opcodes.ACC_STATIC, asMethodTypeName, asMethodTypeDesc, null, null);

        if (Modifier.isInterface(classNode.access)) {
            asMethodType.access |= Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE;
        } else {
            asMethodType.access |= Opcodes.ACC_PRIVATE;
        }

        InsnList asMethodTypeInstructions = new InsnList();
        asMethodType.instructions = asMethodTypeInstructions;
        asMethodTypeInstructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        asMethodTypeInstructions.add(new LdcInsnNode(Type.getObjectType(classNode.name)));
        asMethodTypeInstructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false));
        asMethodTypeInstructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/invoke/MethodType", "fromMethodDescriptorString", "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;", false));
        asMethodTypeInstructions.add(new InsnNode(Opcodes.ARETURN));

        boolean modified = false;

        for (MethodNode methodNode : classNode.methods) {
            Map<AbstractInsnNode, InsnList> replacements = new HashMap<>();

            for (AbstractInsnNode now = methodNode.instructions.getFirst(); now != null; now = now.getNext()) {
                if (now instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) now;
                    if (ldc.cst instanceof Type) {
                        Type type = (Type) ldc.cst;
                        if (type.getSort() == Type.METHOD) {
                            InsnList replacement = new InsnList();
                            replacement.add(new LdcInsnNode(((Type) ldc.cst).getDescriptor()));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, asMethodTypeName, asMethodTypeDesc, false));
                            replacements.put(ldc, replacement);
                        }
                    }
                }
            }

            modified |= !replacements.isEmpty();

            replacements.forEach((node, replacement) -> {
                methodNode.instructions.insert(node, replacement);
                methodNode.instructions.remove(node);
            });
        }

        if (modified) {
            classNode.methods.add(asMethodType);
        }
    }

    /**
     * This one takes code of the following format
     * <p><blockquote><pre>
     *     MethodHandle handle = ldc MethodHandle Sort ClassName Descriptor;
     * </pre></blockquote></p>
     * <p>
     * and converts it to
     * <p><blockquote><pre>
     *     MethodHandle handle = MethodHandles.lookup().[corresponding method](corresponding args);
     * </pre></blockquote></p>
     * <p>
     * Note that this method must be called before {@link Retroindy#handleLdcMethodType(ClassNode)} so MethodTypes are converted properly
     */
    private static void handleLdcMethodHandle(ClassNode classNode) {
        for (MethodNode methodNode : classNode.methods) {
            Map<AbstractInsnNode, InsnList> replacements = new HashMap<>();

            for (AbstractInsnNode now = methodNode.instructions.getFirst(); now != null; now = now.getNext()) {
                if (now instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) now;
                    if (ldc.cst instanceof Handle) {
                        InsnList replacement = new InsnList();
                        Handle handle = (Handle) ldc.cst;

                        replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/invoke/MethodHandles", "lookup", "()Ljava/lang/invoke/MethodHandles$Lookup;", false));

                        if (handle.getTag() == H_GETFIELD) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            handleType(handle.getDesc(), replacement);
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findGetter", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == H_GETSTATIC) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            handleType(handle.getDesc(), replacement);
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findStaticGetter", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == H_PUTFIELD) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            handleType(handle.getDesc(), replacement);
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findSetter", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == H_PUTSTATIC) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            handleType(handle.getDesc(), replacement);
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findStaticSetter", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == Opcodes.H_INVOKEVIRTUAL) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            replacement.add(new LdcInsnNode(Type.getType(handle.getDesc())));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findVirtual", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == Opcodes.H_INVOKESTATIC) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            replacement.add(new LdcInsnNode(Type.getType(handle.getDesc())));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findStatic", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == Opcodes.H_INVOKESPECIAL) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            replacement.add(new LdcInsnNode(Type.getType(handle.getDesc())));
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findSpecial", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == Opcodes.H_NEWINVOKESPECIAL) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(Type.getType(handle.getDesc())));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findConstructor", "(Ljava/lang/Class;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
                        } else if (handle.getTag() == Opcodes.H_INVOKEINTERFACE) {
                            Type classType = Type.getObjectType(handle.getOwner());
                            replacement.add(new LdcInsnNode(classType));
                            replacement.add(new LdcInsnNode(handle.getName()));
                            replacement.add(new LdcInsnNode(Type.getType(handle.getDesc())));
                            replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findVirtual", "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
                        } else {
                            throw new IllegalArgumentException("Unhandled " + handle.getTag());
                        }

                        replacements.put(ldc, replacement);
                    }
                }
            }
            replacements.forEach((node, replacement) -> {
                methodNode.instructions.insert(node, replacement);
                methodNode.instructions.remove(node);
            });
        }
    }

    private static void handleType(String desc, InsnList list) {
        Type type = Type.getType(desc);
        if (type.getSort() == Type.BOOLEAN) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Boolean", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.CHAR) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Character", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.BYTE) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Byte", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.SHORT) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Short", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.INT) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.FLOAT) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Float", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.LONG) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Long", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.DOUBLE) {
            list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/Double", "TYPE", "Ljava/lang/Class;"));
        } else if (type.getSort() == Type.OBJECT) {
            list.add(new LdcInsnNode(type));
        } else {
            throw new IllegalArgumentException("Unhandled " + type.getSort());
        }
    }

    /**
     * This one converts {@code invokedynamic} instructions into regular invocation instructions with the help of
     * additional methods and fields
     * <p>
     * JLS notes:
     * Resolve MethodHandle, MethodType from bsm, static bsmArgs
     * Simulate a invokevirtual (!) on java/lang/invoke/MethodHandle invoke (Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;<other args>)Ljava/lang/invoke/CallSite;
     * No boxing
     * Descriptor is arbitrary (could return Object)
     * If bootstrap is varargs, collect trailing args into varargs array
     * If bootstrap is invoked concurrently, all are allowed to complete, but only one result is used
     * todo:
     * Handle varargs
     * Linking/Runtime exceptions
     * <p>
     * Note that when the JVM bootstraps an invokedynamic instruction, the call stack looks like this:
     * <p><blockquote><pre>
     *      Caused by: java.lang.Exception:
     *          at com.javadeobfuscator.InvokeDynamicExample.boostrapperMethod(Unknown Source)
     *          at java.lang.invoke.CallSite.makeSite(Unknown Source)
     *          at java.lang.invoke.MethodHandleNatives.linkCallSiteImpl(Unknown Source)
     *          at java.lang.invoke.MethodHandleNatives.linkCallSite(Unknown Source)
     *          at com.javadeobfuscator.InvokeDynamicExample.main(Unknown Source)
     * </pre></blockquote></p>
     * <p>
     * Whereas in this approach, the call stack looks like this:
     * <p><blockquote><pre>
     *      Caused by: java.lang.Exception:
     *          at com.javadeobfuscator.InvokeDynamicExample.boostrapperMethod(Unknown Source)
     *          at com.javadeobfuscator.InvokeDynamicExample.INDY_0(Unknown Source)
     *          at com.javadeobfuscator.InvokeDynamicExample.main(Unknown Source)
     * </pre></blockquote></p>
     */
    private static void handleIndy(ClassNode classNode) {
        MethodNode clinit = null;

        for (MethodNode methodNode : classNode.methods) {
            if (methodNode.name.equals("<clinit>") && methodNode.desc.equals("()V")) {
                clinit = methodNode;
            }
        }

        String callsiteArrayName = "CALLSITE_CACHE";
        String callsiteArrayDesc = "Ljava/util/concurrent/atomic/AtomicReferenceArray;";
        {
            Set<String> blacklisted = new HashSet<>();
            for (FieldNode fieldNode : classNode.fields) {
                if (fieldNode.desc.equals(callsiteArrayDesc) && fieldNode.name.startsWith(callsiteArrayName)) {
                    blacklisted.add(fieldNode.name);
                }
            }
            if (!blacklisted.add(callsiteArrayName)) {
                for (int i = 0; i < Integer.MAX_VALUE; i++) {
                    if (blacklisted.add(callsiteArrayName + i)) {
                        callsiteArrayName += i;
                        break;
                    }
                }
            }
        }

        FieldNode callsiteArray = new FieldNode(Opcodes.ASM5, Opcodes.ACC_STATIC, callsiteArrayName, callsiteArrayDesc, null, null);

        int invokeDynamicCount = 0;

        List<MethodNode> newBootstrapMethods = new ArrayList<>();

        for (MethodNode methodNode : classNode.methods) {
            Map<AbstractInsnNode, InsnList> replacements = new HashMap<>();

            if (methodNode.instructions == null)
                continue;

            for (AbstractInsnNode now = methodNode.instructions.getFirst(); now != null; now = now.getNext()) {
                if (now instanceof InvokeDynamicInsnNode) {
                    // name might not matter, but desc does
                    InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) now;

                    int thisId = invokeDynamicCount++;

                    MethodNode bootstrap = new MethodNode(Opcodes.ASM5, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "INDY_" + thisId, indy.desc, null, null);

                    /*
                        Per the JLS §6.4

                        Semantically similar Java code:
                        if (callsiteArray.get(i) == null) {
                            CallSite site = (CallSite) invokebsm;
                            callsiteArray.compareAndSet(i, null, site);
                        }
                        callsiteArray.get(i).invokeExact(params);
                     */

                    LabelNode jumpIfCallsite = new LabelNode();

                    InsnList insns = new InsnList();
                    insns.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, callsiteArray.name, callsiteArray.desc));
                    insns.add(new LdcInsnNode(thisId));
                    insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/atomic/AtomicReferenceArray", "get", "(I)Ljava/lang/Object;", false));
                    insns.add(new JumpInsnNode(Opcodes.IFNONNULL, jumpIfCallsite));

                    insns.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, callsiteArray.name, callsiteArray.desc));
                    insns.add(new LdcInsnNode(thisId));
                    insns.add(new InsnNode(Opcodes.ACONST_NULL));

                    insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/invoke/MethodHandles", "lookup", "()Ljava/lang/invoke/MethodHandles$Lookup;", false));
                    insns.add(new LdcInsnNode(indy.name));
                    insns.add(new LdcInsnNode(Type.getType(indy.desc)));

                    for (Object o : indy.bsmArgs) {
                        insns.add(new LdcInsnNode(o));
                    }

                    insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, indy.bsm.getOwner(), indy.bsm.getName(), indy.bsm.getDesc(), false));
                    insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/atomic/AtomicReferenceArray", "compareAndSet", "(ILjava/lang/Object;Ljava/lang/Object;)Z", false));
                    insns.add(new InsnNode(Opcodes.POP));

                    insns.add(jumpIfCallsite);
                    insns.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, callsiteArray.name, callsiteArray.desc));
                    insns.add(new LdcInsnNode(thisId));
                    insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/concurrent/atomic/AtomicReferenceArray", "get", "(I)Ljava/lang/Object;", false));

                    insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/invoke/CallSite"));
                    insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/CallSite", "getTarget", "()Ljava/lang/invoke/MethodHandle;", false));

                    Type[] types = Type.getMethodType(bootstrap.desc).getArgumentTypes();
                    for (int i = 0, locals = 0; i < types.length; i++) {
                        Type type = types[i];
                        if (type.getSort() == Type.BOOLEAN) {
                            insns.add(new VarInsnNode(Opcodes.ILOAD, locals++));
                        } else if (type.getSort() == Type.CHAR) {
                            insns.add(new VarInsnNode(Opcodes.ILOAD, locals++));
                        } else if (type.getSort() == Type.BYTE) {
                            insns.add(new VarInsnNode(Opcodes.ILOAD, locals++));
                        } else if (type.getSort() == Type.SHORT) {
                            insns.add(new VarInsnNode(Opcodes.ILOAD, locals++));
                        } else if (type.getSort() == Type.INT) {
                            insns.add(new VarInsnNode(Opcodes.ILOAD, locals++));
                        } else if (type.getSort() == Type.FLOAT) {
                            insns.add(new VarInsnNode(Opcodes.FLOAD, locals++));
                        } else if (type.getSort() == Type.LONG) {
                            insns.add(new VarInsnNode(Opcodes.LLOAD, locals));
                            locals += 2;
                        } else if (type.getSort() == Type.DOUBLE) {
                            insns.add(new VarInsnNode(Opcodes.DLOAD, locals));
                            locals += 2;
                        } else if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
                            insns.add(new VarInsnNode(Opcodes.ALOAD, locals++));
                        } else {
                            throw new IllegalArgumentException("Unhandled " + type.getSort());
                        }
                    }

                    insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "invokeExact", bootstrap.desc, false));

                    Type type = Type.getReturnType(bootstrap.desc);
                    if (type.getSort() == Type.VOID) {
                        insns.add(new InsnNode(Opcodes.RETURN));
                    } else if (type.getSort() == Type.BOOLEAN) {
                        insns.add(new InsnNode(Opcodes.IRETURN));
                    } else if (type.getSort() == Type.CHAR) {
                        insns.add(new InsnNode(Opcodes.IRETURN));
                    } else if (type.getSort() == Type.BYTE) {
                        insns.add(new InsnNode(Opcodes.IRETURN));
                    } else if (type.getSort() == Type.SHORT) {
                        insns.add(new InsnNode(Opcodes.IRETURN));
                    } else if (type.getSort() == Type.INT) {
                        insns.add(new InsnNode(Opcodes.IRETURN));
                    } else if (type.getSort() == Type.FLOAT) {
                        insns.add(new InsnNode(Opcodes.FRETURN));
                    } else if (type.getSort() == Type.LONG) {
                        insns.add(new InsnNode(Opcodes.LRETURN));
                    } else if (type.getSort() == Type.DOUBLE) {
                        insns.add(new InsnNode(Opcodes.DRETURN));
                    } else if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
                        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
                        insns.add(new InsnNode(Opcodes.ARETURN));
                    } else {
                        throw new IllegalArgumentException("Unhandled " + type.getSort());
                    }

                    bootstrap.instructions = insns;

                    // gotta compute frames somehow ¯\_(ツ)_/¯
                    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                    writer.visit(Opcodes.ASM5, 0, "a", null, "java/lang/Object", null);
                    bootstrap.accept(writer);
                    ClassReader reader = new ClassReader(writer.toByteArray());
                    ClassNode temp = new ClassNode();
                    reader.accept(temp, 0);
                    bootstrap = temp.methods.get(0);

                    newBootstrapMethods.add(bootstrap);

                    InsnList replacement = new InsnList();
                    replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, bootstrap.name, bootstrap.desc, false));
                    replacements.put(indy, replacement);
                }
            }
            replacements.forEach((node, replacement) -> {
                methodNode.instructions.insert(node, replacement);
                methodNode.instructions.remove(node);
            });
        }

        if (invokeDynamicCount > 0) {
            if (Modifier.isInterface(classNode.access)) {
                callsiteArray.access |= Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
            } else {
                callsiteArray.access |= Opcodes.ACC_PRIVATE;
            }
            classNode.fields.add(callsiteArray);
            classNode.methods.addAll(newBootstrapMethods);

            if (clinit == null) {
                clinit = new MethodNode(Opcodes.ASM5, Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                clinit.instructions = new InsnList();
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
                classNode.methods.add(clinit);
            }

            InsnList initFields = new InsnList();
            initFields.add(new TypeInsnNode(Opcodes.NEW, "java/util/concurrent/atomic/AtomicReferenceArray"));
            initFields.add(new InsnNode(Opcodes.DUP));
            initFields.add(new LdcInsnNode(invokeDynamicCount));
            initFields.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
            initFields.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/util/concurrent/atomic/AtomicReferenceArray", "<init>", "([Ljava/lang/Object;)V", false));
            initFields.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, callsiteArray.name, callsiteArray.desc));

            clinit.instructions.insert(initFields);
        }
    }
}
