package breaking;

import de.tudbut.security.AccessKiller;
import de.tudbut.security.DataKeeper;
import de.tudbut.security.StrictnessBuilder;
import de.tudbut.security.permissionmanager.CallClassRestriction;
import sun.misc.Unsafe;

import java.lang.invoke.LambdaMetafactory;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.util.function.Consumer;

public class DataKeeperBreaker {
    private static final DataKeeper<String> secret = new DataKeeper<>(new CallClassRestriction(AllowedAccessClass.class), StrictnessBuilder.empty(), "Security broken.");


    public static void main(String[] args) throws Throwable {
        AccessKiller.killReflectionFor(AllowedAccessClass.class);
        AccessKiller.killReflectionFor(DataKeeperBreaker.class);

        Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) unsafeField.get(null);
        MethodHandles.lookup();
        Field lookupField = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
        long lookupFieldOffset = unsafe.staticFieldOffset(lookupField);
        MethodHandles.Lookup trustedLookup = (MethodHandles.Lookup) unsafe.getObject(MethodHandles.Lookup.class, lookupFieldOffset);

        // step one: bypass caller check

        String template = DataKeeperBreaker.class.getName();
        String name = AllowedAccessClass.class.getName();

        MethodHandle hashGetter = trustedLookup.findGetter(String.class, "hash", int.class);
        MethodHandle hashSetter = trustedLookup.findSetter(String.class, "hash", int.class);
        MethodHandle valueGetter = trustedLookup.findGetter(String.class, "value", char[].class);
        MethodHandle valueSetter = trustedLookup.findSetter(String.class, "value", char[].class);

        hashSetter.invoke(template, hashGetter.invoke(name));
        valueSetter.invoke(name, valueGetter.invoke(template));

        /*
        if i had figured out this trick sooner, i would not have had to use asm last time... ;-;
        the basic idea is the same, the only difference is that instead of modifying the AllowedAccessClass name's value
        & hash to match DataKeeperBreaker, in which case i would also have had to asm & brute force a hash, i did the
        opposite for the hash, matching DataKeeperBreaker's with AllowedAccessClass', which means the String#equals
        check passes, and the string gets put in the correct hashmap bucket
                            - Crosby
         */

        // step two: bypass lambda check

        MethodHandles.Lookup allowedAccess = MethodHandles.lookup();

        MethodHandle lambdaMethod = allowedAccess.findStatic(DataKeeperBreaker.class, "accessMiddle", MethodType.methodType(void.class, DataKeeper.Accessor.class));
        MethodHandle lambdaMetafactory = LambdaMetafactory.metafactory(allowedAccess, "accept", MethodType.methodType(Consumer.class), MethodType.methodType(void.class, Object.class), lambdaMethod, MethodType.methodType(void.class, DataKeeper.Accessor.class)).getTarget();

        Consumer<DataKeeper.Accessor<String>> accessMiddle = (Consumer<DataKeeper.Accessor<String>>) lambdaMetafactory.invoke();

        secret.access(accessMiddle);
    }

    public static void accessMiddle(DataKeeper.Accessor<String> accessor) {
        System.out.println(accessor.getValue());
    }

    public static class AllowedAccessClass {
        public static void print() {
            secret.access(x -> System.out.println(x.getValue()));
        }
    }
}
