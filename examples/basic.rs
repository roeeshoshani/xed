use std::process::Command;

use arrayvec::ArrayVec;
use xed::{Insn, Operand, Reg, XedAddressWidth, XedInsnIClass, XedMachineMode, XedState};

fn main() {
    // decode_test()
    encode_test();
}

fn encode_test() {
    let xed_state = XedState::new(
        XedMachineMode::XED_MACHINE_MODE_LONG_64,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
    );
    let result = xed_state.encode(&Insn {
        iclass: XedInsnIClass::XED_ICLASS_MOV,
        effective_operand_width_in_bits: 64,
        operands: [
            Operand::Reg(Reg::XED_REG_RAX),
            Operand::Reg(Reg::XED_REG_RDI),
        ]
        .into_iter()
        .collect(),
    });
    println!("{:?}", result);
}

fn decode_test() {
    let stdin = std::io::stdin();
    let mut input = String::new();
    loop {
        input.clear();
        stdin.read_line(&mut input).unwrap();

        dump_operands(&input);
    }
}

fn dump_operands(assembly_line: &str) {
    let bytes = nasm_assemble(&format!("bits 64\n{}", assembly_line));
    let xed_state = XedState::new(
        XedMachineMode::XED_MACHINE_MODE_LONG_64,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
        XedAddressWidth::XED_ADDRESS_WIDTH_64b,
    );
    let insn = xed_state.decode(&bytes).unwrap();
    for i in 0..insn.operands_amount() {
        let op = insn.operand(i).unwrap();
        dbg!(op.name());
        dbg!(op.ty());
        dbg!(op.x_type());
        dbg!(op.visibility());
    }
}

fn nasm_assemble(assembly_code: &str) -> Vec<u8> {
    let asm_file_path = "/tmp/.xed_example_basic_nasm.asm";
    let output_file_path = "/tmp/.xed_example_basic_nasm.bin";
    std::fs::write(asm_file_path, assembly_code.as_bytes()).unwrap();
    let exit_code = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg(asm_file_path)
        .arg("-o")
        .arg(output_file_path)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(exit_code.success());
    std::fs::read(output_file_path).unwrap()
}
