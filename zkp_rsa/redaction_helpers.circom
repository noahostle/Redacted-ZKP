pragma circom 2.0.0;

template RH_Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;
    var e2 = 1;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

template RH_IsZero() {
    signal input in;
    signal output out;

    signal inv;
    inv <-- in != 0 ? 1 / in : 0;

    out <== -in * inv + 1;
    in * out === 0;
}

template RH_IsEqual() {
    signal input in[2];
    signal output out;

    component isZero = RH_IsZero();
    isZero.in <== in[1] - in[0];
    out <== isZero.out;
}

template RH_LessThan(n) {
    signal input in[2];
    signal output out;

    component n2b = RH_Num2Bits(n + 1);
    n2b.in <== in[0] + (1 << n) - in[1];
    out <== 1 - n2b.out[n];
}

template CompressedRedactionMask(N, SENTINEL) {
    signal input masked[N];
    signal input msg[N];
    signal input msg_len;
    signal input reveal[N];

    component msgLenBound = RH_LessThan(16);
    msgLenBound.in[0] <== msg_len;
    msgLenBound.in[1] <== N + 1;
    msgLenBound.out === 1;

    signal active[N];
    signal hidden[N];
    signal visible[N];
    signal marker[N];
    signal emit[N];
    signal token[N];
    signal prefix[N + 1];
    signal slotCount[N];
    signal slotSelect[N][N];
    signal slotCountAcc[N][N + 1];
    signal slotValueAcc[N][N + 1];

    component activeLt[N];
    component msgByteBits[N];
    component visibleNotZero[N];
    component visibleNotSentinel[N];
    component slotEq[N][N];

    prefix[0] <== 0;

    for (var i = 0; i < N; i++) {
        activeLt[i] = RH_LessThan(16);
        activeLt[i].in[0] <== i;
        activeLt[i].in[1] <== msg_len;
        active[i] <== activeLt[i].out;

        msgByteBits[i] = RH_Num2Bits(8);
        msgByteBits[i].in <== msg[i];

        reveal[i] * (reveal[i] - 1) === 0;
        reveal[i] * (1 - active[i]) === 0;
        msg[i] * (1 - active[i]) === 0;

        hidden[i] <== active[i] * (1 - reveal[i]);

        if (i == 0) {
            marker[i] <== hidden[i];
        } else {
            marker[i] <== hidden[i] * reveal[i - 1];
        }

        visible[i] <== active[i] * reveal[i];
        visible[i] * marker[i] === 0;

        emit[i] <== visible[i] + marker[i];
        emit[i] * (emit[i] - 1) === 0;

        token[i] <== visible[i] * msg[i] + marker[i] * SENTINEL;
        prefix[i + 1] <== prefix[i] + emit[i];

        visibleNotZero[i] = RH_IsEqual();
        visibleNotZero[i].in[0] <== msg[i];
        visibleNotZero[i].in[1] <== 0;
        visible[i] * visibleNotZero[i].out === 0;

        visibleNotSentinel[i] = RH_IsEqual();
        visibleNotSentinel[i].in[0] <== msg[i];
        visibleNotSentinel[i].in[1] <== SENTINEL;
        visible[i] * visibleNotSentinel[i].out === 0;
    }

    for (var j = 0; j < N; j++) {
        slotCountAcc[j][0] <== 0;
        slotValueAcc[j][0] <== 0;

        for (var i = 0; i < N; i++) {
            slotEq[i][j] = RH_IsEqual();
            slotEq[i][j].in[0] <== prefix[i];
            slotEq[i][j].in[1] <== j;

            slotSelect[i][j] <== emit[i] * slotEq[i][j].out;
            slotCountAcc[j][i + 1] <== slotCountAcc[j][i] + slotSelect[i][j];
            slotValueAcc[j][i + 1] <== slotValueAcc[j][i] + slotSelect[i][j] * token[i];
        }

        slotCount[j] <== slotCountAcc[j][N];
        slotCount[j] * (slotCount[j] - 1) === 0;
        masked[j] === slotValueAcc[j][N];
    }
}
